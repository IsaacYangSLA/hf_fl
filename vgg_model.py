#!/usr/bin/env python3
"""A configurable Hugging Face Hub-compatible VGG classifier for CIFAR-10."""

from __future__ import annotations

import torch
from huggingface_hub import PyTorchModelHubMixin
from torch import nn


class VGG(
    nn.Module,
    PyTorchModelHubMixin,
    library_name="pytorch",
    tags=["pytorch", "federated-learning", "vgg", "cifar10"],
):
    """VGG-11 topology adapted to 32x32 RGB images."""

    _CONFIG: tuple[int | str, ...] = (
        64,
        "M",
        128,
        "M",
        256,
        256,
        "M",
        512,
        512,
        "M",
        512,
        512,
        "M",
    )

    def __init__(
        self,
        num_classes: int = 10,
        width_multiplier: float = 1.0,
        dropout: float = 0.2,
    ) -> None:
        super().__init__()
        if num_classes <= 0:
            raise ValueError("num_classes must be positive")
        if width_multiplier <= 0:
            raise ValueError("width_multiplier must be positive")
        if not 0.0 <= dropout < 1.0:
            raise ValueError("dropout must be in [0, 1)")

        self.num_classes = num_classes
        self.width_multiplier = width_multiplier
        self.dropout = dropout
        layers: list[nn.Module] = []
        input_channels = 3
        output_channels = input_channels
        for value in self._CONFIG:
            if value == "M":
                layers.append(nn.MaxPool2d(kernel_size=2, stride=2))
                continue
            output_channels = max(1, int(round(int(value) * width_multiplier)))
            layers.extend(
                [
                    nn.Conv2d(input_channels, output_channels, kernel_size=3, padding=1),
                    nn.ReLU(inplace=True),
                ]
            )
            input_channels = output_channels

        self.features = nn.Sequential(*layers)
        self.pool = nn.AdaptiveAvgPool2d((1, 1))
        self.classifier = nn.Sequential(
            nn.Flatten(),
            nn.Dropout(p=dropout),
            nn.Linear(output_channels, num_classes),
        )

    def forward(self, images: torch.Tensor) -> torch.Tensor:
        if images.ndim != 4 or images.shape[1:] != (3, 32, 32):
            raise ValueError(
                f"VGG expects [batch, 3, 32, 32], received {tuple(images.shape)}"
            )
        return self.classifier(self.pool(self.features(images)))
