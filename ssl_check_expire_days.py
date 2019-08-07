import time
import datetime
import sys

# the following try/except block will make the custom check compatible with any Agent version
try:
    # first, try to import the base class from old versions of the Agent...
    from checks import AgentCheck
    import subprocress

    # polyfill for datadog v6 function
    def get_subprocess_output(command, log):
        completed = subprocess.run(command, capture_output=True)
        return (completed.stdout, completed.stderr, completed.returncode)


except ImportError:
    # ...if the above failed, the check is running in Agent version 6 or later
    from datadog_checks.checks import AgentCheck
    from datadog_checks.utils.subprocess_output import get_subprocess_output


class SSLCheckExpireDays(AgentCheck):
    def check(self, instance):
        metric = "ssl.expire_in_days"
        site = instance['site']
        tag = "site:" + site # generate the tags
        command = ["timeout", "10", "bash", "-c", "openssl s_client -showcerts -servername " + site + " -connect " + site + ":443 2>/dev/null | openssl x509 -noout -dates | grep notAfter | cut -f 2 -d\= | xargs -0 -I arg date -d arg '+%s'"];
        (output, err, returncode) = get_subprocess_output(command, self.log, False)
        if output:
            output = output.rstrip("\n")
            d0 = int(time.time())
            d1 = int(output)
            delta = d1 - d0
            days = delta / 24 / 60 / 60 # convert the timestamp to days
            self.gauge(metric, int(days), tags=[tag])
        else:
            self.gauge(metric, -1, tags=[tag])
