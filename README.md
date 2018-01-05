# Underpants

## A reverse HTTP proxy that authenticates requests through Google OAuth.

Suppose you are a Google Apps customer and suppose you want to restrict access to some web servers to just the folks in your organization. Like, for instance, if you're building your internal apps on AWS. Pain in the ass, right? So put underpants in between the world and your backends and you can use your Google credentials to get in.

## NOTE

Underpants will currently not work if built with Go 1.9 due to a [breaking change](https://go-review.googlesource.com/c/go/+/38194) in `net/http`. A fix is in the works.

## Installation

```
go get github.com/kellegous/underpants
```

## Configuration

Your underpants are configured through a silly little JSON file. Here's an example:
<pre>
{
  "host" : "underpants.company.com",
  "oauth" : {
    "domain"        : "company.com",
    "client-id"     : "oauth-client-id",
    "client-secret" : "oauth-client-secret"
  },
  "use-strict-security-headers": true,
  "certs" : [
    {
      "crt" : "/path/to/crt.pem",
      "key" : "/path/to/key.pem"
    }
  ],
  "routes" : [
    {
      "from" : "public.company.com",
      "to"   : "http://localhost:8080"
    }
  ]
}
</pre>

The `certs` section is optional and its absence will cause your underpants proxy to operate on pure HTTP. The key file may be encrypted so
long as it is in encrypted PEM format with proper `Proc-Type` and `Dek-Info` headers. If you do not know what that means, just use openssl
and that is what you will end up with.

You can get your oauth-client-id and oauth-client-secret by creating a project on [Google's API Console](https://code.google.com/apis/console).

If your configuration can stomach it, enable `use-strict-security-headers` to
get some extra peace of mind.  This will block clickjacking, disable downstream
HTTP caching, and turn on `Strict-Transport-Security` if HTTPS.

For more granular access control, you can configure groups and their membership
in the JSON file.  Once groups are configured, routes will deny all users who
are not a member of one of the authorized groups by default.  The special `*`
group can be used to allow any authenticated user access to the route.  See
`underpants.sample.groups.json` for a configuration sample.

## Running

Just run it; it's an executable.

```
underpants
```

## Some TODO's
 * Handle non-transactional traffic, like web sockets.
