package httpapi

import (
	"net/http"
	"net/url"

	"github.com/IsaacYangSLA/hf_fl/packages/jobs/internal/domain"
)

// studyMethods deliberately recognizes complete route shapes before identity
// processing, just like the existing job routes. Unknown actions never dispatch.
func studyMethods(parts []string) []string {
	if len(parts) == 1 {
		return []string{"GET", "POST"}
	}
	if len(parts) < 2 || !domain.ValidIdentifier(parts[1]) {
		return nil
	}
	if len(parts) == 2 {
		return []string{"GET"}
	}
	if len(parts) == 3 {
		switch parts[2] {
		case "settings":
			return []string{"PUT"}
		case "application":
			return []string{"GET"}
		case "applications":
			return []string{"GET", "POST"}
		}
	}
	if len(parts) == 5 && parts[2] == "applications" && domain.ValidIdentifier(parts[3]) {
		switch parts[4] {
		case "approve", "reject", "withdraw":
			return []string{"POST"}
		}
	}
	return nil
}

func (s *Server) studies(w http.ResponseWriter, r *http.Request, actor string, parts []string) error {
	ctx := r.Context()
	if len(parts) == 1 {
		if r.Method == http.MethodPost {
			body, e := jsonBody(r, "name")
			if e != nil {
				return e
			}
			key, e := idempotency(r)
			if e != nil {
				return e
			}
			value, e := s.manager.CreateStudy(ctx, actor, body, key)
			if e != nil {
				return e
			}
			return view(w, http.StatusCreated, value, "")
		}
		limit, cursor, e := studyPage(r)
		if e != nil {
			return e
		}
		value, e := s.manager.ListStudies(ctx, actor, limit, cursor)
		if e != nil {
			return e
		}
		return writeJSON(w, http.StatusOK, value)
	}
	id := parts[1]
	if len(parts) == 2 {
		value, e := s.manager.GetStudy(ctx, actor, id)
		if e != nil {
			return e
		}
		return view(w, http.StatusOK, value, "")
	}
	if len(parts) == 3 {
		switch parts[2] {
		case "settings":
			body, e := jsonBody(r, "description", "registration_open")
			if e != nil {
				return e
			}
			description, ok := body["description"].(string)
			if !ok {
				return domain.Err(422, "invalid_request")
			}
			open, ok := boolValue(body["registration_open"])
			if !ok {
				return domain.Err(422, "invalid_request")
			}
			expected, e := version(r)
			if e != nil {
				return e
			}
			key, e := idempotency(r)
			if e != nil {
				return e
			}
			value, e := s.manager.PutStudySettings(ctx, actor, id, description, open, expected, key)
			if e != nil {
				return e
			}
			return view(w, http.StatusOK, value, "")
		case "application":
			value, e := s.manager.GetStudyApplication(ctx, actor, id)
			if e != nil {
				return e
			}
			return writeJSON(w, http.StatusOK, value)
		case "applications":
			if r.Method == http.MethodGet {
				limit, cursor, e := studyPage(r)
				if e != nil {
					return e
				}
				value, e := s.manager.ListStudyApplications(ctx, actor, id, limit, cursor)
				if e != nil {
					return e
				}
				return writeJSON(w, http.StatusOK, value)
			}
			body, e := jsonBody(r, "participant_id", "message")
			if e != nil {
				return e
			}
			participant, ok := body["participant_id"].(string)
			if !ok {
				return domain.Err(422, "invalid_request")
			}
			message := ""
			if raw, present := body["message"]; present {
				message, ok = raw.(string)
				if !ok {
					return domain.Err(422, "invalid_request")
				}
			}
			key, e := idempotency(r)
			if e != nil {
				return e
			}
			value, e := s.manager.ApplyToStudy(ctx, actor, id, participant, message, key)
			if e != nil {
				return e
			}
			return view(w, http.StatusAccepted, value, Prefix+"/studies/"+url.PathEscape(id)+"/application")
		}
	}
	action := parts[4]
	allowed := []string{"reason"}
	if action == "withdraw" {
		allowed = nil
	}
	body, e := jsonBody(r, allowed...)
	if e != nil {
		return e
	}
	reason := ""
	if raw, present := body["reason"]; present {
		var ok bool
		reason, ok = raw.(string)
		if !ok {
			return domain.Err(422, "invalid_request")
		}
	}
	expected, e := version(r)
	if e != nil {
		return e
	}
	key, e := idempotency(r)
	if e != nil {
		return e
	}
	value, e := s.manager.ReviewStudyApplication(ctx, actor, id, parts[3], action, reason, expected, key)
	if e != nil {
		return e
	}
	return view(w, http.StatusOK, value, "")
}

func studyPage(r *http.Request) (int, string, error) {
	query := r.URL.Query()
	limit, e := queryInt(query, "limit", 50, 1, 100)
	if e != nil {
		return 0, "", e
	}
	cursor, e := queryText(query, "cursor", 4096)
	return limit, cursor, e
}
