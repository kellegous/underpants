# Notes

We are forking Underpants from https://github.com/kellegous/underpants, and submitted a PR request
https://github.com/kellegous/underpants/pull/32 to incorporate changes made to deal with setting
up Underpants behind a proxy.

However we are still waiting from response from the author and will temporarily rename the app
depedencies, so we can streamline our development and deploy process. Once the PR above is 
approved, we will be using the original repo instead.

---

# Underpants

## A reverse HTTP proxy that authenticates requests through OAuth2.

Suppose you are a Google Apps customer and suppose you want to restrict access to some web servers to just the folks in your organization. Like, for instance, if you're building your internal apps on AWS. Pain in the ass, right? So put underpants in between the world and your backends and you can use your Google credentials to get in.

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
    "provider"      : "google",
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

## Available Providers
 1. [Google](examples/underpants.http.json)
 2. [Okta](examples/underpants.okta.json)

### Google
You can get your oauth-client-id and oauth-client-secret by creating a project on [Google's API Console](https://code.google.com/apis/console). You will use that for your `client-id` and `client-secret`. Generally, you will also want to use the `domain` configuration to limit authentication to a particular domain.

### Okta
For testing, you can create a [developer account](https://developer.okta.com/). Configuration of okta requires `client-id`, `client-secret` and `base-url` which will point to the domain for your okta instance (i.e. https://example.okta.com).

## Additional Details

The `certs` section is optional and its absence will cause your underpants proxy to operate on pure HTTP. The key file may be encrypted so
long as it is in encrypted PEM format with proper `Proc-Type` and `Dek-Info` headers. If you do not know what that means, just use openssl
and that is what you will end up with.

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
