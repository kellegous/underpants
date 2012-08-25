# Underpants
## A reverse HTTP proxy that authenticates requests through Google OAuth.

Suppose you are a Google Apps customer and suppose you want to restrict access to some web servers to just the folks in your organization. Like, for instance, if you're building your internal apps on AWS. Pain in the ass, right? So put underpants in between the world and your backends and you can use your Google credentials to restrict access.

## Installation

```
go install github.com/kellegous/underpants
```

## Configuration

Your underpants are configured through a silly little JSON file. Here's an example:
<pre>
{
  "host" : "entry.company.com",
  "oauth" : {
    "domain"        : "company.com",
    "client-id"     : "oauth-client-id",
    "client-secret" : "oauth-client-secret",
    "scope"         : "https://www.googleapis.com/auth/userinfo.profile https://www.googleapis.com/auth/userinfo.email"
  },
  "routes" : [
    {
      "from" : "public.company.com",
      "to"   : "localhost:8080"
    }
  ]
}
</pre>

## Running

Just run it; it's an executable.

```
underpants
```

## Some TODO's
 * Add some TODO's