# CertificateChecker

## Overview
CertificateChecker is a .NET Framework 4.7 application designed to validate and monitor SSL/TLS certificates. It ensures that certificates are valid, not expired, and meet security standards. This tool is ideal for system administrators, developers, and IT professionals who need to maintain secure communication channels.

## Features
- **Certificate Validation**: Checks the validity of SSL/TLS certificates.
- **Expiration Monitoring**: Alerts users when certificates are nearing expiration.
- **Customizable Configuration**: Allows users to specify target domains or servers for certificate checks.
- **Detailed Logging**: Provides comprehensive logs for auditing and troubleshooting.
- **User-Friendly Interface**: Simple and intuitive command-line interface for ease of use.

## Requirements
- **Target Framework**: .NET Framework 4.7
- **Operating System**: Windows 7 or later
- **Dependencies**: Ensure that the required .NET Framework version is installed.

## Usage
1. Clone the repository or download the source code.
2. Open the solution in Visual Studio 2022.
3. Build the project to restore dependencies and compile the application.
4. Run the application from the command line or Visual Studio debugger.
5. Configure the `App.config` file to specify domains or servers to monitor.

## Configuration
The `App.config` file contains settings for the application:
- **TargetDomains**: A list of domains to check for certificate validity.
- **AlertThreshold**: Number of days before expiration to trigger alerts.
- **LogFilePath**: Path to save log files.

Example configuration:

```xml
<configuration>
  <appSettings> 
    <add key="TargetDomains" value="example.com, anotherdomain.com" /> 
    <add key="AlertThreshold" value="30" /> 
    <add key="LogFilePath" value="C:\Logs\CertificateChecker.log" /> 
  </appSettings> 
</configuration>
```

## Logging
Logs are generated in the specified file path and include:
- Timestamp of the check
- Domain or server name
- Certificate status (valid, expired, or nearing expiration)
- Detailed error messages, if any

## License
This project is licensed under the MIT License. See the LICENSE file for details.

