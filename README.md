# OpenVPN Client Learn Address Script Plugin

Runs an external script in the background for when a client is added, updated, or deleted from OpenVPN's internal address tables. The results are not used at all but also do not block the main openvpn process.

The idea of the plugin is to do as little as possible, and let the external binary do all the heavy lifting itself, and is built on top of https://github.com/fac/auth-script-openvpn but targeting learn-address rather than auth.

## Installation

Compile the shared library with `make plugin` and copy `openvpn-plugin-learn-address-script.so` into your `lib/openvpn/plugins/` folder.

Copy your external script onto the machine in a sane place, making sure it's executable by the user openvpn is running as.

Configure the plugin in your openvpn config, passing the path to the external script as the second argument:

    plugin /path/to/openvpn-plugin-learn-address-script.so /path/to/external/script.sh downrate uprate

The plugin will also pass any strings provided after the script name as arguments to the script execution:

    plugin /path/to/openvpn-plugin-learn-address-script.so /path/to/external/script.sh downrate uprate (add|update|delete) ip user

## External Script requirements

The script used to handle "learn address" event needs to:

* Be executable by the user openvpn runs as
* Exit with status code 0
* Not depend on `PATH` variable (eg, don't use `/usr/bin/env` in shebang)

## License

See LICENSE.
