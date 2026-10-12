"""Historical external cleanup with real SQL/broker/materializer/node ledgers."""
from __future__ import annotations

import base64
from dataclasses import asdict, replace
from datetime import datetime, timedelta, timezone
import hashlib
import json
from pathlib import Path
import subprocess
import tempfile
from types import SimpleNamespace
import unittest

from cryptography.hazmat.primitives.asymmetric import rsa
from sqlalchemy import select

from hf2l_jobs import models
from hf2l_jobs.application import Manager
from hf2l_jobs.broker import BrokerSettings, WorkloadBroker
from hf2l_jobs.collection import CollectionError
from hf2l_jobs.database import create_database
from hf2l_jobs.domain import Error, JobSpec
from hf2l_jobs.executor import ExecutionIdentity, ResourceLimits
from hf2l_jobs.node_agent import NodeAgent
from hf2l_jobs.participant_cleanup import ExternalCleanup, purge_assignment
from hf2l_jobs.participants import ApprovedExternalNode, ExternalParticipantService, ExternalParticipantAgent
from hf2l_jobs.remote_node import RemoteAssignment, RemoteNodeMaterializer, LocalNodeSecrets, purge_private_tree
from hf2l_jobs.source import RegistryCatalog
from hf2l_jobs.resources import atomic_json
from hf2l_jobs.workflow import DatasetBinding
from test_participants import RecordedExchange, certificate
from test_remote_node import RecordingRuntime
from test_gateway import certificate_bundle
from hf2l_jobs.execution_proxy import ProxySupervisor
from hf2l_jobs.broker import stable_workload_principal


class CleanupClient:
    def __init__(self, cleanup, broker, certificate_thumbprint):
        self.cleanup, self.broker, self.thumbprint = cleanup, broker, certificate_thumbprint
        self.calls = []
        self.offline = False
        self.lose_ack = False

    def request(self, identity, token, operation, body=None):
        self.calls.append(operation)
        if self.offline:
            raise Error(503, "external_manager_unavailable")
        actor = self.broker.authenticate_node("Bearer " + token,
            verified_peer_thumbprint=self.thumbprint, grant_validator=self.cleanup.check_node_grant)
        if operation == "purge-plan":
            return self.cleanup.purge_plan(actor)
        if operation == "purged":
            result = self.cleanup.confirm_purged(actor, body["confirmed"])
            if self.lose_ack:
                self.lose_ack = False
                raise Error(503, "external_manager_unavailable")
            return result
        raise AssertionError(operation)


class ExternalCleanupTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.key = rsa.generate_private_key(public_exponent=65537, key_size=2048)

    def setUp(self):
        self.temporary = tempfile.TemporaryDirectory(prefix="hf2l-participant-purge-")
        self.addCleanup(self.temporary.cleanup)
        self.root = Path(self.temporary.name)
        repository = self.root / "approved-repo"
        repository.mkdir()
        for command in (["git", "init", "-q", str(repository)],
                ["git", "-C", str(repository), "config", "user.email", "fixture@test.invalid"],
                ["git", "-C", str(repository), "config", "user.name", "Fixture"]):
            subprocess.run(command, check=True, capture_output=True)
        content = b'raise RuntimeError("cleanup must never import workload")\\n'
        (repository / "plugin.py").write_bytes(content)
        (repository / "nested").mkdir()
        (repository / "nested" / "opaque.py").write_bytes(b"NEVER_IMPORT = True\\n")
        for command in (["git", "-C", str(repository), "add", "."],
                        ["git", "-C", str(repository), "commit", "-qm", "Pinned fixture"]):
            subprocess.run(command, check=True, capture_output=True)
        self.commit = subprocess.check_output(["git", "-C", str(repository), "rev-parse", "HEAD"],
                                             text=True).strip()
        self.manifest = {"plugin.py": hashlib.sha256(content).hexdigest(),
                         "nested/opaque.py": hashlib.sha256((repository/"nested"/"opaque.py").read_bytes()).hexdigest()}
        self.database = create_database("sqlite:///" + str(self.root / "manager.sqlite"))
        self.addCleanup(self.database.close)
        self.now = datetime.now(timezone.utc)
        self.manager = Manager(self.database, b"cleanup-pagination-secret-32-bytes", clock=lambda: self.now)
        self.thumbprint = certificate("cleanup-approved-node")
        self.broker = WorkloadBroker(BrokerSettings("https://workloads.test", "exchange", "gateway", "nodes",
                                                   self.key.public_key(), self.key),
                                    clock=lambda: self.now.timestamp())
        with self.database.transaction() as session:
            session.add(models.Project(id="project", name="Project"))
            session.flush()
            session.add(models.ProjectMember(project_id="project", principal_id="alice", role="submitter"))
            session.add(models.ApprovedSource(id="source", project_id="project", url="",
                allowed_commits=[self.commit], details_json={"mirror_path": str(repository / ".git")}))
            session.add(models.RuntimeImage(id="runtime", project_id="project", digest="sha256:" + "b"*64))
            session.add(models.Pool(id="cpu", name="CPU", node_id="owner", healthy=True,
                cpu_millicores=4000, memory_bytes=8<<30, disk_bytes=8<<30,
                sandbox_profiles=["runsc-cpu-v1"]))
            session.add(models.ParticipantBinding(id="data", project_id="project", participant_id="alice",
                                                 node_id="external", dataset_label="Approved data"))
            session.add(models.ParticipantBinding(id="data-bob", project_id="project", participant_id="bob",
                                                 node_id="external", dataset_label="Approved Bob data"))
        registry = RegistryCatalog.from_database(self.database)
        self.provisioner = SimpleNamespace(root=self.root / "manager-jobs",
            registry=registry, exchange=RecordedExchange(self.broker.settings.workload_issuer),
            _space_id=lambda job_id: "space-" + job_id)
        self.node_config = ApprovedExternalNode("external", self.thumbprint,
            {"data": DatasetBinding(kind="npz", path="/job/data/data.npz"),
             "data-bob": DatasetBinding(kind="synthetic")},
            resources={"cpu_millicores":500,"memory_bytes":128<<20,"disk_bytes":256<<20})
        self.service = ExternalParticipantService(self.manager,self.provisioner,self.broker,[self.node_config])
        self.cleanup = ExternalCleanup(self.service)
        self.job = self.new_job("first")
        self.local_root = self.root / "external-node"
        self.local_root.mkdir(mode=0o700)
        self.runtime = RecordingRuntime(self.local_root)
        self.runtime.confirm_absent=lambda identity:identity.key not in self.runtime.specs
        self.local_node = NodeAgent(self.runtime,self.local_root/"node.sqlite","external","external",
                                   ResourceLimits(4000,4<<30,16<<30),watchdog_interval=60)
        self.addCleanup(self.local_node.close)
        self.materializer = RemoteNodeMaterializer(self.local_root/"inputs",registry,
            node_id="external",pool_id="external",
            dataset_bindings=lambda assigned:{"data":{"kind":"npz","path":"/job/data/data.npz"}},
            auxiliary_reserver=self.local_node.charge_auxiliary_bytes)
        self.client = CleanupClient(self.cleanup,self.broker,self.thumbprint)
        node_broker = WorkloadBroker(replace(self.broker.settings,private_key=None),
                                     clock=lambda:self.now.timestamp())
        self.agent = ExternalParticipantAgent(self.client,self.materializer,self.local_node,node_broker,
                                               node_certificate_thumbprint=self.thumbprint)
        self.dataset = self.root/"approved-dataset.npz"
        self.dataset.write_bytes(b"opaque approved input")

    def spec(self):
        return {"project_id":"project","name":"External cleanup","source_id":"source",
            "source_commit":self.commit,"runtime_image":"runtime","plugin":"plugin",
            "participants":[{"participant_id":"alice","dataset_binding":"data","mode":"external"},
                            {"participant_id":"bob","dataset_binding":"data-bob","mode":"external"}],
            "components":[{"component_id":"owner","role":"owner","resources":{"pool_id":"cpu",
                "cpu_millicores":1000,"memory_bytes":1<<30,"disk_bytes":1<<30}}],
            "target_round":1,"max_duration_seconds":3600}

    def new_job(self,key):
        job=self.manager.create_job("alice",self.spec(),key)
        path=self.provisioner.root/job["id"]
        (path/"source").mkdir(parents=True)
        (path/"source"/"plugin.py").write_bytes((self.root/"approved-repo"/"plugin.py").read_bytes())
        (path/"source"/"nested").mkdir()
        (path/"source"/"nested"/"opaque.py").write_bytes((self.root/"approved-repo"/"nested"/"opaque.py").read_bytes())
        (path/".source.json").write_text(json.dumps({"source_id":"source","commit":self.commit,
                                                   "manifest":self.manifest}))
        return job

    def reserve_log_budgets(self, *, job=None, attempt_number=None):
        # Share scheduler-like admission through the real retention ledger.
        from test_participants import ExternalParticipantFixture
        return ExternalParticipantFixture.reserve_log_budgets(
            self,job=job,attempt_number=attempt_number)

    def prepare(self,job=None,attempt_number=1,run=True):
        job=job or self.job
        try:
            enrollment=self.service.get_enrollment("alice",job["id"],"alice")
        except Error:
            version=self.manager.get_job("alice",job["id"])["version"]
            enrollment=self.service.enroll("alice",job["id"],"alice","external",version,"enroll-"+job["id"])
        with self.database.transaction() as session:
            row=session.get(models.Job,job["id"])
            row.state="RUNNING";row.current_attempt=attempt_number;row.epoch=attempt_number
            row.deadline_at=self.now+timedelta(hours=1)
            attempt=session.scalar(select(models.Attempt).where(models.Attempt.job_id==row.id,
                                                                 models.Attempt.number==attempt_number))
            if attempt is None:
                attempt=models.Attempt(job_id=row.id,number=attempt_number,epoch=attempt_number,state="RUNNING")
                session.add(attempt);session.flush()
            attempt.state="RUNNING"
        self.reserve_log_budgets(job=job,attempt_number=attempt_number)
        dispatch=self.service.bootstrap_credentials(enrollment["id"])
        actor=self.broker.authenticate_node("Bearer "+dispatch["node_token"],
            verified_peer_thumbprint=self.thumbprint,grant_validator=self.service.check_node_grant)
        result=self.service.assignment(actor,execution_certificate_thumbprint=certificate(actor.attempt_id),
                                       proxy_id="proxy-"+actor.attempt_id)
        identity=ExecutionIdentity(actor.job_id,actor.attempt_id,actor.component_id,actor.epoch)
        assigned=RemoteAssignment(identity,"external","external",ResourceLimits(500,128<<20,256<<20),
            JobSpec.model_validate(result["runtime_config"]["spec"]),"sha256:"+"b"*64,external_participant_id="alice")
        execution=self.materializer.plan(assigned)
        self.local_node.reserve(execution)
        self.materializer.reserve(assigned)
        self.materializer.prepare(identity,result["runtime_config"])
        (Path(execution.state_path)/"artifacts"/"result.bin").write_bytes(b"owned output")
        if run:self.local_node.start(identity)
        return actor,identity,execution

    def stop(self,actor,identity):
        self.local_node.stop(identity)
        self.local_node.release(identity)
        self.service.confirm_stopped(actor,termination_confirmed=True)
        with self.database.transaction() as session:
            attempt=session.get(models.Attempt,identity.attempt_id)
            attempt.revocation_confirmed=True;attempt.termination_confirmed=True;attempt.state="FAILED"

    def terminal(self,job=None,authorized=True):
        job=job or self.job
        with self.database.transaction() as session:
            row=session.get(models.Job,job["id"])
            row.state="FAILED";row.cleanup_status="purge_pending" if authorized else "none"
        return self.manager.get_job("alice",job["id"])

    def actor_for(self,identity,scopes=("purge",)):
        with self.database.transaction(immediate=False) as session:
            record=session.scalar(select(models.ProvisioningResource).where(
                models.ProvisioningResource.job_id==identity.job_id,
                models.ProvisioningResource.attempt_id==identity.attempt_id,
                models.ProvisioningResource.component_id==identity.component_id,
                models.ProvisioningResource.kind=="external_execution"))
            token=self.broker.issue_node(node_id="external",pool_id="external",job_id=identity.job_id,
                attempt_id=identity.attempt_id,component_id=identity.component_id,grant_id=record.id,
                epoch=identity.epoch,certificate_thumbprint=self.thumbprint,scopes=scopes)
        actor=self.broker.authenticate_node("Bearer "+token,verified_peer_thumbprint=self.thumbprint,
                                          grant_validator=lambda value:True)
        return actor,token

    def test_two_historical_attempts_purge_owned_bytes_preserve_dataset_and_audit(self):
        actor1,identity1,execution1=self.prepare()
        first_log="attempt one retained log"
        self.service.append_logs(actor1,{"identity":asdict(identity1),"source_id":identity1.key,
            "offset":0,"next_offset":len(first_log.encode()),"content":first_log,
            "complete":True,"truncated":False})
        self.assertEqual((Path(execution1.source_path)/"nested").stat().st_mode & 0o777,0o555)
        self.stop(actor1,identity1)
        actor2,identity2,execution2=self.prepare(attempt_number=2)
        second_log="attempt two retained log"
        self.service.append_logs(actor2,{"identity":asdict(identity2),"source_id":identity2.key,
            "offset":0,"next_offset":len(second_log.encode()),"content":second_log,
            "complete":True,"truncated":False})
        self.stop(actor2,identity2)
        job=self.terminal()
        calls=[]
        def dispatch(node,document):
            self.assertEqual(node,"external")
            identity=ExecutionIdentity(**{name:document["enrollment"][name] for name in
                                          ("job_id","attempt_id","component_id","epoch")})
            actor=self.broker.authenticate_node("Bearer "+document["node_token"],
                verified_peer_thumbprint=self.thumbprint,grant_validator=self.cleanup.check_node_grant)
            self.assertEqual(actor.scopes,frozenset({"purge"}))
            calls.append(identity)
            return self.agent.receive(document)
        self.service.node_dispatch=dispatch
        self.assertTrue(self.cleanup.purge_job(job))
        self.assertEqual(set(calls),{identity1,identity2})
        self.assertFalse(Path(execution1.source_path).exists())
        self.assertFalse(Path(execution1.state_path).exists())
        self.assertFalse(Path(execution1.config_path).exists())
        self.assertFalse(Path(execution2.config_path).exists())
        self.assertEqual(self.dataset.read_bytes(),b"opaque approved input")
        self.assertTrue((self.materializer.directories.job_path(job["id"])/".owner.json").exists())
        self.assertEqual(len(self.local_node.inventory()),2)
        self.assertTrue(all(row["disk_released"] for row in self.local_node.inventory()))
        self.assertTrue(all(row["auxiliary_bytes"] == 0 for row in self.local_node.inventory()))
        self.assertTrue(self.cleanup.purge_job(job))
        with self.database.transaction(immediate=False) as session:
            attempts=list(session.scalars(select(models.Attempt).where(models.Attempt.job_id==job["id"])))
            self.assertEqual(len(attempts),2)
            self.assertTrue(all(attempt.revocation_confirmed for attempt in attempts))
            resources=list(session.scalars(select(models.ProvisioningResource).where(
                models.ProvisioningResource.job_id==job["id"],
                models.ProvisioningResource.kind.in_(("external_execution","external_enrollment",
                                                     "external_execution_certificate")))))
            self.assertTrue(all(row.state=="deleted" and row.deleted_at is not None for row in resources))
            logs=list(session.scalars(select(models.ProvisioningResource).where(
                models.ProvisioningResource.job_id==job["id"],
                models.ProvisioningResource.kind=="log_budget")))
            self.assertEqual(len(logs),4)
            self.assertTrue(all(row.deleted_at is None and row.retained
                                and row.details_json["retention_charge_released"] is False
                                and row.details_json["retention_charged_bytes"]==1024**2 for row in logs))
            self.assertEqual(session.get(models.Project,"project").retained_bytes,4*1024**2)
            chunks=list(session.scalars(select(models.LogChunk).where(
                models.LogChunk.job_id==job["id"]).order_by(models.LogChunk.attempt_number)))
            self.assertEqual([chunk.data for chunk in chunks],[first_log,second_log])
            self.assertTrue(all(chunk.deleted_at is None for chunk in chunks))

    def test_undelivered_bootstrap_confirms_absence_without_deleting_any_input(self):
        version=self.manager.get_job("alice",self.job["id"])["version"]
        enrollment=self.service.enroll("alice",self.job["id"],"alice","external",version,"enroll-unused")
        with self.database.transaction() as session:
            job=session.get(models.Job,self.job["id"])
            job.state="RUNNING";job.epoch=1
            attempt=session.scalar(select(models.Attempt).where(models.Attempt.job_id==job.id))
            attempt.state="RUNNING"
        self.reserve_log_budgets()
        document=self.service.bootstrap_credentials(enrollment["id"])
        actor=self.broker.authenticate_node("Bearer "+document["node_token"],
            verified_peer_thumbprint=self.thumbprint,grant_validator=self.service.check_node_grant)
        self.assertEqual(self.local_node.inventory(),())
        self.service.confirm_stopped(actor)
        with self.database.transaction() as session:
            attempt=session.get(models.Attempt,actor.attempt_id)
            attempt.state="FAILED";attempt.revocation_confirmed=True;attempt.termination_confirmed=True
        self.terminal()
        self.service.node_dispatch=lambda node,document:self.agent.receive(document)
        self.assertTrue(self.cleanup.purge_job(self.job))
        self.assertEqual(self.local_node.inventory(),())
        self.assertEqual(self.dataset.read_bytes(),b"opaque approved input")

    def test_unknown_component_bytes_with_absent_assignment_remain_unconfirmed(self):
        version=self.manager.get_job("alice",self.job["id"])["version"]
        enrollment=self.service.enroll("alice",self.job["id"],"alice","external",version,"enroll-orphan")
        with self.database.transaction() as session:
            job=session.get(models.Job,self.job["id"]);job.state="RUNNING";job.epoch=1
            attempt=session.scalar(select(models.Attempt).where(models.Attempt.job_id==job.id))
            attempt.state="RUNNING"
        self.reserve_log_budgets()
        document=self.service.bootstrap_credentials(enrollment["id"])
        actor=self.broker.authenticate_node("Bearer "+document["node_token"],
            verified_peer_thumbprint=self.thumbprint,grant_validator=self.service.check_node_grant)
        self.service.confirm_stopped(actor)
        with self.database.transaction() as session:
            attempt=session.get(models.Attempt,actor.attempt_id)
            attempt.state="FAILED";attempt.revocation_confirmed=True;attempt.termination_confirmed=True
        self.terminal()
        component=self.materializer.directories.job_path(self.job["id"])/"components"/actor.component_id
        source=component/"source";source.mkdir(parents=True);(source/"orphan").write_bytes(b"unknown")
        self.service.node_dispatch=lambda node,document:self.agent.receive(document)
        self.assertFalse(self.cleanup.purge_job(self.job))
        self.assertEqual((source/"orphan").read_bytes(),b"unknown")
        with self.database.transaction(immediate=False) as session:
            record=session.scalar(select(models.ProvisioningResource).where(
                models.ProvisioningResource.kind=="external_execution"))
            self.assertIsNone(record.deleted_at)

    def test_foreign_resource_ownership_blocks_dispatch_and_deletion(self):
        actor,identity,execution=self.prepare();self.stop(actor,identity);self.terminal()
        with self.database.transaction() as session:
            resource=session.scalar(select(models.ProvisioningResource).where(
                models.ProvisioningResource.kind=="external_enrollment"))
            resource.ownership_json={**resource.ownership_json,"job_id":"foreign"}
        dispatched=[]
        self.service.node_dispatch=lambda node,document:dispatched.append(document)
        with self.assertRaises(Error):
            self.cleanup.purge_job(self.job)
        self.assertEqual(dispatched,[])
        self.assertTrue(Path(execution.source_path).exists())
        self.assertFalse(self.local_node.inventory()[0]["disk_released"])

    def test_sealed_secret_and_opaque_build_copies_hold_auxiliary_charge_until_deleted(self):
        actor,identity,execution=self.prepare()
        parent=Path(execution.source_path).parent
        build=parent/"build-inputs";build.mkdir(mode=0o700)
        (build/"opaque.whl").write_bytes(b"opaque build bytes never decoded")
        atomic_json(parent/"build-input-manifest.json",{"opaque.whl":"owned"},mode=0o400)
        local_secrets=LocalNodeSecrets(self.local_root/"sealed-secrets",{})
        binding=asdict(identity)
        directory=local_secrets.resolver._directory(binding,create=True)
        import os
        os.close(directory)
        sealed=local_secrets.resolver._path(binding)
        atomic_json(sealed,{"schema_version":1,**binding,"role":"participant",
            "references":{"model_key":"model-reference"},"options":{"model_key":"fixture-sealed-value"}},mode=0o400)
        original=self.root/"approved-secret-source"
        original.write_bytes(b"keep administrator-owned source")
        self.agent.private_cleanup=lambda target:False
        self.stop(actor,identity);self.terminal()
        actor,token=self.actor_for(identity)
        with self.assertRaises(Error):
            purge_assignment(self.agent,actor,identity,token)
        inventory=self.local_node.inventory()[0]
        self.assertGreater(inventory["auxiliary_bytes"],0)
        self.assertFalse(inventory["disk_released"])
        self.assertTrue(sealed.is_file())
        self.assertFalse(build.exists())
        def cleanup(target):
            if local_secrets.resolver.cleanup(asdict(target),termination_confirmed=True) is not True:
                return False
            return purge_private_tree(local_secrets.resolver._path(asdict(target)).parent)
        self.agent.private_cleanup=cleanup
        self.assertEqual(purge_assignment(self.agent,actor,identity,token)["state"],"purged")
        self.assertFalse(sealed.exists())
        self.assertEqual(original.read_bytes(),b"keep administrator-owned source")
        inventory=self.local_node.inventory()[0]
        self.assertEqual(inventory["auxiliary_bytes"],0)
        self.assertTrue(inventory["disk_released"])
        self.assertEqual(self.dataset.read_bytes(),b"opaque approved input")

    def test_proxy_cleanup_failure_keeps_auxiliary_charge_and_receipt_pending(self):
        actor,identity,_=self.prepare();self.stop(actor,identity);self.terminal()
        actor,token=self.actor_for(identity)
        requests=[]
        self.agent.proxy_supervisor=SimpleNamespace(purge=lambda target,termination_confirmed:
            requests.append((target,termination_confirmed)) or False)
        with self.assertRaises(Error):
            purge_assignment(self.agent,actor,identity,token)
        self.assertEqual(requests,[(identity,True)])
        inventory=self.local_node.inventory()[0]
        self.assertGreater(inventory["auxiliary_bytes"],0)
        self.assertFalse(inventory["disk_released"])
        with self.database.transaction(immediate=False) as session:
            self.assertIsNone(session.get(models.ProvisioningResource,actor.grant_id).deleted_at)

    def test_real_proxy_credentials_and_socket_are_deleted_before_auxiliary_release(self):
        actor,identity,execution=self.prepare()
        bundle=certificate_bundle(self.root)
        sockets=tempfile.TemporaryDirectory(prefix="hf2lp-")
        self.addCleanup(sockets.cleanup)
        supervisor=ProxySupervisor(self.local_root/"proxies",client_ca_certificate=bundle["ca"][2],
            client_ca_key=bundle["ca"][3],broker=self.agent.broker,
            exchange_endpoint="https://exchange.test",gateway_endpoint="https://gateway.test",
            service_ca_file=bundle["ca"][2],grant_lookup=lambda *ignored:None,socket_root=sockets.name)
        self.addCleanup(supervisor.close)
        self.agent.proxy_supervisor=supervisor
        principal=stable_workload_principal(self.broker.settings.workload_issuer,identity.job_id,
                                            identity.component_id,"alice")
        binding=supervisor.binding(SimpleNamespace(id=identity.job_id,deadline_at=self.now+timedelta(hours=1)),
            SimpleNamespace(id=identity.attempt_id,job_id=identity.job_id,epoch=identity.epoch),
            SimpleNamespace(component_id=identity.component_id,participant_id="alice"),
            "space-"+identity.job_id,principal)
        proxy_root=supervisor.root/identity.job_id/"attempts"/identity.attempt_id/identity.component_id
        self.assertTrue((proxy_root/"proxy-key.pem").is_file())
        self.assertTrue(Path(binding["proxy_endpoint"]).is_socket())
        self.stop(actor,identity);self.terminal()
        actor,token=self.actor_for(identity)
        self.assertEqual(purge_assignment(self.agent,actor,identity,token)["state"],"purged")
        self.assertFalse(proxy_root.exists())
        self.assertFalse(Path(binding["proxy_endpoint"]).parent.exists())
        self.assertTrue(Path(bundle["ca"][3]).is_file())
        inventory=self.local_node.inventory()[0]
        self.assertTrue(inventory["disk_released"])
        self.assertEqual(inventory["auxiliary_bytes"],0)

    def test_missing_node_row_with_private_executor_reservation_cannot_ack_purge(self):
        version=self.manager.get_job("alice",self.job["id"])["version"]
        enrollment=self.service.enroll("alice",self.job["id"],"alice","external",version,"enroll-private")
        with self.database.transaction() as session:
            job=session.get(models.Job,self.job["id"]);job.state="RUNNING";job.epoch=1
            attempt=session.scalar(select(models.Attempt).where(models.Attempt.job_id==job.id))
            attempt.state="RUNNING"
        self.reserve_log_budgets()
        document=self.service.bootstrap_credentials(enrollment["id"])
        actor=self.broker.authenticate_node("Bearer "+document["node_token"],
            verified_peer_thumbprint=self.thumbprint,grant_validator=self.service.check_node_grant)
        identity=ExecutionIdentity(actor.job_id,actor.attempt_id,actor.component_id,actor.epoch)
        spec=JobSpec.model_validate(self.manager.get_job("alice",self.job["id"])["spec"])
        assignment=RemoteAssignment(identity,"external","external",ResourceLimits(500,128<<20,256<<20),
            spec,"sha256:"+"b"*64,external_participant_id="alice")
        self.runtime.reserve(self.materializer.plan(assignment))
        self.assertEqual(self.local_node.inventory(),())
        self.assertFalse(self.local_node.confirm_absent(identity))
        self.service.confirm_stopped(actor)
        with self.database.transaction() as session:
            attempt=session.get(models.Attempt,actor.attempt_id)
            attempt.state="FAILED";attempt.revocation_confirmed=True;attempt.termination_confirmed=True
        self.terminal()
        self.service.node_dispatch=lambda node,document:self.agent.receive(document)
        self.assertFalse(self.cleanup.purge_job(self.job))
        with self.database.transaction(immediate=False) as session:
            resource=session.scalar(select(models.ProvisioningResource).where(
                models.ProvisioningResource.kind=="external_execution"))
            self.assertIsNone(resource.deleted_at)
        self.assertIn(identity.key,self.runtime.specs)

    def test_only_true_confirmation_updates_historical_resource(self):
        actor,identity,_=self.prepare();self.stop(actor,identity);self.terminal()
        actor,token=self.actor_for(identity)
        for value in (False,1,"true",None):
            with self.assertRaises(Error):
                self.cleanup.confirm_purged(actor,value)
        with self.database.transaction(immediate=False) as session:
            self.assertIsNone(session.get(models.ProvisioningResource,actor.grant_id).deleted_at)

    def test_purging_one_job_preserves_a_second_running_jobs_private_bytes(self):
        actor1,identity1,execution1=self.prepare();self.stop(actor1,identity1);self.terminal()
        other=self.new_job("second")
        actor2,identity2,execution2=self.prepare(other)
        actor,token=self.actor_for(identity1)
        self.assertEqual(purge_assignment(self.agent,actor,identity1,token)["state"],"purged")
        self.assertFalse(Path(execution1.source_path).exists())
        self.assertTrue(Path(execution2.source_path).is_dir())
        self.assertEqual((Path(execution2.state_path)/"artifacts"/"result.bin").read_bytes(),b"owned output")
        self.assertEqual(self.local_node.inspect(identity2).state,"RUNNING")
        self.assertEqual(self.dataset.read_bytes(),b"opaque approved input")

    def test_retention_expiry_authorizes_cleanup_without_user_purge_flag(self):
        actor,identity,_=self.prepare();self.stop(actor,identity)
        self.terminal(authorized=False)
        with self.database.transaction() as session:
            session.get(models.Job,self.job["id"]).artifacts_expire_at=self.now-timedelta(seconds=1)
        actor,token=self.actor_for(identity)
        self.assertTrue(self.cleanup.check_node_grant(actor))
        self.assertEqual(purge_assignment(self.agent,actor,identity,token)["state"],"purged")

    def test_terminal_job_within_retention_cannot_purge(self):
        actor,identity,execution=self.prepare();self.stop(actor,identity);self.terminal(authorized=False)
        actor,token=self.actor_for(identity)
        self.assertFalse(self.cleanup.check_node_grant(actor))
        with self.assertRaises(Error):
            self.cleanup.purge_job(self.job)
        self.assertTrue(Path(execution.source_path).exists())

    def test_unconfirmed_runtime_or_revocation_keeps_storage_and_resources(self):
        actor,identity,execution=self.prepare();self.terminal()
        self.assertFalse(self.cleanup.check_node_grant(self.actor_for(identity)[0]))
        with self.assertRaises(Error):
            self.cleanup.purge_job(self.job)
        self.assertTrue(Path(execution.state_path).exists())
        self.local_node.stop(identity);self.local_node.release(identity)
        self.service.confirm_stopped(actor)
        with self.database.transaction() as session:
            session.get(models.Attempt,identity.attempt_id).termination_confirmed=True
        self.assertFalse(self.cleanup.check_node_grant(self.actor_for(identity)[0]))

    def test_foreign_identity_certificate_and_mixed_scopes_are_denied(self):
        actor,identity,_=self.prepare();self.stop(actor,identity);self.terminal()
        actor,_=self.actor_for(identity)
        for changed in (replace(actor,job_id="foreign"),replace(actor,component_id="foreign"),
                        replace(actor,epoch=99),replace(actor,node_id="foreign"),
                        replace(actor,certificate_thumbprint=certificate("foreign")),
                        replace(actor,scopes=frozenset({"purge","assignment"}))):
            self.assertFalse(self.cleanup.check_node_grant(changed))

    def test_disabled_input_approval_still_cleans_owned_output_preserving_input(self):
        actor,identity,_=self.prepare();self.stop(actor,identity);self.terminal()
        with self.database.transaction() as session:
            session.get(models.ParticipantBinding,"data").enabled=False
        self.service.nodes["external"]=replace(self.node_config,enabled=False,dataset_bindings={"other":DatasetBinding(kind="synthetic")})
        actor,token=self.actor_for(identity)
        self.assertTrue(self.cleanup.check_node_grant(actor))
        purge_assignment(self.agent,actor,identity,token)
        self.assertEqual(self.dataset.read_bytes(),b"opaque approved input")

    def test_offline_node_retains_disk_accounting_and_central_resource(self):
        actor,identity,execution=self.prepare();self.stop(actor,identity);self.terminal()
        self.service.node_dispatch=lambda node,document:(_ for _ in ()).throw(Error(503,"node_offline"))
        self.assertFalse(self.cleanup.purge_job(self.job))
        self.assertFalse(self.local_node.inventory()[0]["disk_released"])
        self.assertTrue(Path(execution.source_path).exists())
        with self.database.transaction(immediate=False) as session:
            resource=session.scalar(select(models.ProvisioningResource).where(
                models.ProvisioningResource.kind=="external_execution"))
            self.assertIsNone(resource.deleted_at)
            self.assertTrue(resource.retained)

    def test_offline_manager_refuses_node_deletion(self):
        actor,identity,execution=self.prepare();self.stop(actor,identity);self.terminal()
        actor,token=self.actor_for(identity)
        self.client.offline=True
        with self.assertRaises(Error):
            purge_assignment(self.agent,actor,identity,token)
        self.assertTrue(Path(execution.source_path).exists())
        self.assertFalse(self.local_node.inventory()[0]["disk_released"])

    def test_lost_purge_ack_replays_tombstone_without_releasing_foreign_storage(self):
        actor,identity,execution=self.prepare();self.stop(actor,identity);self.terminal()
        actor,token=self.actor_for(identity)
        self.client.lose_ack=True
        with self.assertRaises(Error):
            purge_assignment(self.agent,actor,identity,token)
        self.assertEqual(purge_assignment(self.agent,actor,identity,token)["state"],"purged")
        self.assertFalse(Path(execution.source_path).exists())
        self.assertEqual(self.dataset.read_bytes(),b"opaque approved input")

    def test_linked_or_modified_pinned_source_is_not_followed_or_acknowledged(self):
        actor,identity,execution=self.prepare();self.stop(actor,identity);self.terminal()
        actor,token=self.actor_for(identity)
        source=Path(execution.source_path)/"plugin.py"
        source.chmod(0o600)
        source.write_bytes(b"changed immutable source")
        with self.assertRaises(CollectionError):
            purge_assignment(self.agent,actor,identity,token)
        source.parent.chmod(0o700)
        source.unlink();source.symlink_to(self.dataset)
        with self.assertRaises(CollectionError):
            purge_assignment(self.agent,actor,identity,token)
        self.assertEqual(self.dataset.read_bytes(),b"opaque approved input")
        with self.database.transaction(immediate=False) as session:
            resource=session.get(models.ProvisioningResource,actor.grant_id)
            self.assertIsNone(resource.deleted_at)
        self.assertFalse(self.local_node.inventory()[0]["disk_released"])

    def test_historical_purge_cannot_delete_shared_files_of_new_running_attempt(self):
        actor1,identity1,execution1=self.prepare();self.stop(actor1,identity1)
        actor2,identity2,_=self.prepare(attempt_number=2)
        self.terminal()
        actor,token=self.actor_for(identity1)
        # Even a compromised/stale central plan cannot bypass the local ledger.
        real_request=self.client.request
        self.client.request=lambda identity,token,operation,body=None: {
            "identity":asdict(identity),"node_id":"external","pool_id":"external",
            "termination_confirmed":True,"revocation_confirmed":True,"preserve_dataset_inputs":True,
            "spec_digest":self.materializer.assignment(identity1).job_spec.digest,"participant_id":"alice",
            "source_manifest":self.manifest} if operation=="purge-plan" else real_request(identity,token,operation,body)
        with self.assertRaises(Error):
            purge_assignment(self.agent,actor,identity1,token)
        self.assertTrue(Path(execution1.source_path).exists())
        self.assertFalse(self.local_node.inventory()[0]["disk_released"])


if __name__=="__main__":
    unittest.main()
