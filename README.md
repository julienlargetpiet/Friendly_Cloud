# Friendly_Cloud

![logo.jpg](static/logo.jpg)

A cloud server written in Go allowing account creation, adding, downloading and removing files.

## Philosophy

The server does not make use of cookies to authenticate users after their connection, but rather of a randomly temporary password authentication mechanism. 

So, everytime the user get out of the website, he is disconnected.

And he has to click only on the website link to go back for example if he does not want to be disconnected.

Because the server does not communicate an authentication cookie, and that pasing a password by URL is not secure, each time the user connects to the account, a temporary random password is generated only available for next connection on the next page. When he connects to the next page, the same mechanism is applied until the user get out of the website. 

A running example is here:

<a href="https://nuagesympa.xyz/">here</a>

# Setting Up the server

## Database

Using `MySQL (5.7+)` or `Mariadb (10.5+)`

```
CREATE DATABASE friendly_cloud;
CREATE TABLE credentials (username VARCHAR(15), password VARCHAR(16), temp_password TINYTEXT);
```

## AES key

Modify the default `AES key` at line `16` of `main.go` (must be 32 of characters)

This key is used to cipher the random temporary password.

## Username

By default, all usernames are available appart from the `banned_usernames` at line `54`

If you want to only allow certain usernames, in `only_usernames` at line `35`, set the boolean `only_usrs` to `true` at line `37`.

## HTTPS

It is absolutely necessary to activate `https` on this server.

If you are not using a reverse proxy like `NGINX` that handles `https` (configured via certbot for example), do the following:

at the end of `main.go`, change from:

```
// NOT IN PRODUCTION
err = http.ListenAndServe("127.0.0.1:" + port_run, mux)
if err != nil {
  fmt.Println("Failed to start server...")
  fmt.Print(err)
  return
}
```

To:

```
// IN PRODUCTION
err := http.ListenAndServeTLS(":443", "cert.pem", "key.pem", nil)
if err != nil {
    log.Fatalf("ListenAndServeTLS failed: %v", err)
}
```

## Is it very scalable ?

No, because to much `UPDATE` SQL request.




