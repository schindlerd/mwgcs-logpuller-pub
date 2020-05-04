# McAfee Web Gateway Cloud Services (WGCS) Logpuller Script

Script to get McAfee Web Gateway Cloud Service logs from McAfee SaaS-API. Logs are downloaded to ```'OutputLog.$NowUnixEpoch$.csv'``` and can be forwarded to a remote syslog host or SIEM when ```syslogEnable``` is set to ```'True'```.

> **Note:**
>
> When forwarding is used the downloaded CSV is transformed into a JSON stream. Configure your syslog/SIEM input correspondingly.

Timestamp is automatically adjusted with the last successful time of request. The corresponding configuration option ```requestTimestampFrom``` is updated after each run of the script.

The script is using McAfee SaaS Message API ver. 5

Field reference:
<https://docs.mcafee.com/bundle/web-gateway-cloud-service-product-guide/page/GUID-BDF3E4F1-1625-4569-BE80-D528CE521BC1.html>

General API reference:
<https://docs.mcafee.com/bundle/web-gateway-cloud-service-product-guide/page/GUID-B24F5DAE-F9BB-44F7-976A-BF2245CBADF3.html>

## Usage

- Download script and configuration file.
- Make script executable and adjust the configuration file to your needs.
- Run it periodically via cron for example.

## Configuration

This table explains the necessary configuration options:
| Section | Option | Value Type | Description | Example |
|---------|--------|------------|-------------|---------|
| ```saas``` | ```saasCustomerID``` | INT (Mandatory) | Your WGCS customer ID without the leading 'c' | ```123456789``` |
|  | ```saasUserID``` | STR (mandatory) | Usually your tenant e-mail address | ```foo@example.com``` |
|  | ```saasPassword``` | STR (mandatory) | Your WGCS tenant password | ```my53cr37p455``` |
|  | ```saasHost``` | STR (mandatory) | Europe: ```eu.msg.mcafee``` / US: ```msg.mcafeesaas.com``` | ```eu.msg.mcafeesaas.com``` |
| ```request``` | ```requestTimestampFrom``` | INT (mandatory) | Epoch timestamp of last successful request; dynamically set to last execution time; if initially set to 0 value is dynamically adjusted to ```Now - 24h``` | ```1588458908``` |
|  | ```chunkIncrement``` | INT (mandatory) | Requests are splitted into chunks if time between last request and execution is bigger than this value (seconds) | ```3600``` |
|  | ```connectionTimeout``` | INT (mandatory) | Time to wait for request response (seconds) | ```180``` |
|  | ```outputDirCSV``` | STR (optional) | Specify different output directory for downloaded CSV file ```'OutputLog.$NowUnixEpoch$.csv'``` **IMPORTANT**: directoy must exist! | ```/var/tmp/wgcslogs``` |
| ```proxy``` | ```proxyURL``` | STR (optional) | If you are behind a proxy you can configure a corresponding URL here (format: ```http://PROXY_SERVER:PORT``` or ```http://USER:PASSWORD@PROXY_SERVER:PORT)``` | ```http://proxy.example.com:8080``` |
| ```syslog``` | ```syslogEnable``` | BOOL (mandatory) | Enable message forwarding in form of a JSON stream; either 'True' or 'False' | ```True``` |
|  | ```syslogHost``` | STR (mandatory) | IP or hostname of remote syslog host/Log Management/SIEM | ```graylog.example.com``` |
|  | ```syslogPort``` | INT (mandatory) | Port for remote syslog input | ```5555``` |
|  | ```syslogProto``` | STR (mandatory) | Must be either ```'TCP'``` or ```'UDP'``` | ```UDP``` |
|  | ```syslogKeepCSV``` | BOOL (mandatory) | Keep the downloaded CSV (```'True'```) or delete after forwarding (```'False'```) | ```False``` |

## Disclaimer

This is an **UNOFFICIAL** project and is **NOT** sponsored or supported by **McAfee, Inc**.

## Credits and Links

Special thanks go to [@tux78](https://github.com/tux78), Jeff Ebeling and Erik Elsasser from McAfee for providing the codebase for my reworked implementation.

- Please refer to this McAfee Community Article for further inspiration - <https://community.mcafee.com/t5/Web-Gateway/Example-Bash-Script-for-Log-Pull-from-Web-Gateway-Cloud-Service/m-p/619639#M19479>
- A PowerShell implementation can be found here - <https://github.com/tux78/WGCSLogPull>
