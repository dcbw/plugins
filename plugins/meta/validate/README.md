## Validation plugin

This plugin will validate that a given PrevResult accurately reflects the
state of the container and host system.  It expects to be a chained plugin.

## Usage
You should use this plugin as part of a network configuration list.

A sample standalone config list (with the file extension .conflist) might look like:

```json
{
        "cniVersion": "0.3.1",
        "name": "mynet",
        "plugins": [
                {
                        "type": "ptp",
                        "ipam": {
                                "type": "host-local",
                                "subnet": "172.16.30.0/24",
                                "routes": [
                                        {
                                                "dst": "0.0.0.0/0"
                                        }
                                ]
                        }
                },
                {
                        "type": "validate"
                }
        ]
}
```

