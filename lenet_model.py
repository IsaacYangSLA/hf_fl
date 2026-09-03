#!/usr/bin/env python3
"""A small Hugging Face Hub-compatible LeNet model for 28x28 grayscale images."""

from __future__ import annotations

import torch
from huggingface_hub import PyTorchModelHubMixin
from torch import nn


class LeNet(
    nn.Module,
    PyTorchModelHubMixin,
    library_name="pytorch",
    tags=["pytorch", "federated-learning", "lenet"],
):
    """Classic LeNet-style classifier with JSON-serializable configuration."""

    def __init__(self, num_classes: int = 10) -> None:
        super().__init__()
        self.num_classes = num_classes
        self.features = nn.Sequential(
            nn.Conv2d(1, 6, kernel_size=5),
            nn.ReLU(),
            nn.AvgPool2d(kernel_size=2, stride=2),
            nn.Conv2d(6, 16, kernel_size=5),
            nn.ReLU(),
            nn.AvgPool2d(kernel_size=2, stride=2),
        )
        self.classifier = nn.Sequential(
            nn.Flatten(),
            nn.Linear(16 * 4 * 4, 120),
            nn.ReLU(),
            nn.Linear(120, 84),
            nn.ReLU(),
            nn.Linear(84, num_classes),
        )

    def forward(self, images: torch.Tensor) -> torch.Tensor:
        if images.ndim != 4 or images.shape[1:] != (1, 28, 28):
            raise ValueError(
                f"LeNet expects [batch, 1, 28, 28], received {tuple(images.shape)}"
            )
        return self.classifier(self.features(images))
