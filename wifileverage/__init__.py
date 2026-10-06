"""WiFiLeverage - authorized network-segmentation assessment framework.

WiFiLeverage helps penetration testers validate whether wireless network
segmentation controls (client/station isolation, guest-to-corporate
separation, inter-VLAN boundaries) are actually enforced during an
*authorized* engagement.

The framework is authorization-gated: no active probe runs until an
engagement scope has been loaded and the operator has attested that they
have written permission to test the in-scope assets.
"""

from .version import __version__

__all__ = ["__version__"]
