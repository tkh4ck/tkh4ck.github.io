# HCSC 2025 - Mystery Model

## Description

The world is all about AI nowadays. Look at all these tech giants holding their hands on their own, super secret models. Researchers claim that once you have the model, it's game over. Is it really true tho? I am handing you a model, it has the flag hidden in plain sight. Carve it out!

BTW: if you want some extra challenge, don't check the attached `summary.txt` file.

Remarks from the creator:
* Offline challenge, no VPN connection is required
* latest `challenge.zip` sha256sum: `d9d1f4734f4d650755a60e3ee7f880616a9d6b6a434e001504a084a0c7ad6b32`
* you do not need a GPU to solve this challenge

**Flag format**: `HCSC{...}`

*By MJ*

## Metadata

- Filename: [`challenge.zip`](files/challenge.zip)
- Tags: `machine learning`, `pytorch`, `neural network`
- Points: 400
- Number of solvers: 49

## Solution

We got a saved `pytorch` model `mystery_model.pt` and the output of the training of the model.

```
==========================================================================================
Layer (type:depth-idx)                   Output Shape              Param #
==========================================================================================
FlagModel                                [1, ??*]                   --
├─Linear: 1-1                            [1, 128]                  256
├─ReLU: 1-2                              [1, 128]                  --
├─Linear: 1-3                            [1, ??*]                   6,708
==========================================================================================
Total params: 6,964
Trainable params: 6,964
Non-trainable params: 0
Total mult-adds (Units.MEGABYTES): 0.01
==========================================================================================
Input size (MB): 0.00
Forward/backward pass size (MB): 0.00
Params size (MB): 0.03
Estimated Total Size (MB): 0.03
==========================================================================================
* Left as an exercise to the reader to determine the flag length.
* The flag is ASCII-encoded.
```

I used LLMs (ChatGPT) to generate a load script in Python and used the `pytorch/pytorch` docker image to execute it.

```python
import torch
import torch.nn as nn

# Load the checkpoint properly
checkpoint = torch.load("mystery_model.pt", map_location=torch.device('cpu'))
state_dict = checkpoint["model"]

# Detect input and output sizes from the first and last layer weights
input_size = state_dict["fc1.weight"].shape[1]   # columns of fc1.weight
output_size = state_dict["fc2.weight"].shape[0]  # rows of fc2.weight

# Dynamically define model with correct sizes
class FlagModel(nn.Module):
    def __init__(self):
        super(FlagModel, self).__init__()
        self.fc1 = nn.Linear(input_size, 128)
        self.relu = nn.ReLU()
        self.fc2 = nn.Linear(128, output_size)

    def forward(self, x):
        x = self.fc1(x)
        x = self.relu(x)
        x = self.fc2(x)
        return x

# Instantiate and load state dict
model = FlagModel()
model.load_state_dict(state_dict)
model.eval()

# Create dummy input matching the expected input size
dummy_input = torch.ones((1, input_size))

# Run inference
with torch.no_grad():
    output = model(dummy_input).squeeze().round().int()

# Convert output tensor to ASCII string
flag = ''.join(chr(c.item()) for c in output)
print(f"HCSC{{{flag}}}")
```

The flag is: `HCSC{is_this_really_the_flag_or_is_ai_hallucinating}`