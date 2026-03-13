## About the Application

This application provides a user-friendly graphical interface that enables non-expert users to manage Linux `iptables` rules without dealing directly with command-line syntax. It focuses on the `INPUT` chain and supports IPv4, TCP, and UDP traffic, including optional TCP flag matching. The interface allows users to define multiple IP addresses as either a whitelist or a blacklist, making firewall configuration more accessible and easier to manage. Its main purpose is to hide the complexity of `iptables` commands behind intuitive forms while also providing live feedback on rule activity.

> **Note:** This application works only on Unix-based operating systems or within a WSL environment, since it relies on Linux `iptables` functionality.