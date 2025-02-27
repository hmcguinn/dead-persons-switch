# Cryptographic Dead Person's Switch

A trustless dead person's switch implementation using verifiable delay functions (VDFs) and threshold secret sharing. This project was created as a final project for COMP 590: Privacy Enhancing Technologies.

## Overview

This project implements a cryptographic dead person's switch that automatically releases encrypted content after a specified time period if the user stops checking in. The implementation:

- Eliminates the need for fully-trusted third parties
- Ensures content cannot be accessed before the intended time
- Provides assurance that content can be eventually released
- Maintains privacy and security through cryptographic guarantees

## Usage

```
# Example usage
from timelock import TimeLockClient, TimeLockUser

# Create a new dead person's switch with your secret content
plaintext = "Your secret information here"
check_in_interval = 3600  # seconds (1 hour)
client = TimeLockClient(plaintext, check_in_interval)

# Register with multiple servers (threshold of 3, total 5)
client.register(5)

# Perform regular check-ins to reset the timer
client.check_in()

# ---- After timer expiration ----

# Someone wanting to retrieve the content
user = TimeLockUser(servers)
user.request_start()  # Get VDF parameters
user.solve()          # Compute the VDF (takes time)
user.present_solved() # Present proof to servers
user.combine()        # Combine shares
plaintext = user.decrypt()  # Get the original content
```

For a more detailed explanation of the cryptographic principles and protocol design, please see [hmcguinn.com/pdf/dead-persons-switch.pdf](https://hmcguinn.com/pdf/dead-persons-switch.pdf)
