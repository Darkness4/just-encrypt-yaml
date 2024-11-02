# just-encrypt-yaml

Just encrypt string values in YAML with asymmetric PEM keys. Needed for GitOps when we need to encrypt locally, and decrypt server-side.

## Usage

### Generate PEM keys

```bash
openssl req -x509 -days 1825 -nodes -newkey rsa:4096 -keyout "tls.key" -out "tls.crt" -subj "/CN=secret-controller/O=secret-controller"
```

### Encrypt

**secret.yaml**

```yaml
mySecret: "mySecretValue"

wireguard:
  wg0:
    privateKey: "myPrivateKey"
```

**Execute:**

```bash
just-encrypt-yaml --key tls.crt  [--out secret-sealed.yaml] secret.yaml
```

**secret-sealed.yaml**

```yaml
mySecret: AgALQpFfOS5AF...
wireguard:
  wg0:
     privateKey: AgBBuKY...
```

### Decrypt

**secret-sealed.yaml**

```yaml
mySecret: AgALQpFfOS5AF...
wireguard:
  wg0:
     privateKey: AgBBuKY...
```

**Execute:**

```bash
just-encrypt-yaml --decrypt --key tls.kej [--out secret-sealed-decrypted.yaml] secret-sealed.yaml
```

**secret.yaml**

```yaml
mySecret: "mySecretValue"

wireguard:
  wg0:
    privateKey: "myPrivateKey"
```

### Help

```bash
NAME:
   just-encrypt-yaml - Encrypt or decrypt YAML files using RSA keys

USAGE:
   just-encrypt-yaml [global options] command [command options] <file>

COMMANDS:
   help, h  Shows a list of commands or help for one command

GLOBAL OPTIONS:
   --key value    Path to the private RSA key (for decryption) or certificate (for encryption)
   --decrypt      Decrypt the YAML file (default: false)
   --out value    Path to the output file
   --help, -h     show help
   --version, -v  print the version
```

## Usage with gomplate

***config.boot.enc***

```groovy
interfaces {
    wireguard wg0 {
        address "10.0.0.1/24"
        address "fd00:1234:5678::1/64"
        description "Peer VPN"
        peer peer01 {
            allowed-ips "10.0.0.2/32"
            allowed-ips "fd00:1234:5678::2/128"
            public-key "gVO0f7i3UsdWWkLYOVzawcndBuKC6FggVLWtdkXoFWQ="
        }
        port "51820"
        private-key "{{ .wireguard.wg0.privateKey }}"
    }
}
```

**secret-sealed.yaml**

```yaml
wireguard:
  wg0:
    privateKey: AgBBuKY...
```

**Execute:**

```bash
just-encrypt-yaml --decrypt --key tls.key --out secret.yaml secret-sealed.yaml
gomplate -c ".=secret.yaml" -f config.boot.enc -o config.boot
```

**config.boot**

```groovy
interfaces {
    wireguard wg0 {
        address "10.0.0.1/24"
        address "fd00:1234:5678::1/64"
        description "Peer VPN"
        peer peer01 {
            allowed-ips "10.0.0.2/32"
            allowed-ips "fd00:1234:5678::2/128"
            public-key "gVO0f7i3UsdWWkLYOVzawcndBuKC6FggVLWtdkXoFWQ="
        }
        port "51820"
        private-key "gJVybSkgiEJLNOUpz8nTfKGUpLXSy6OMvLqLkLIPOUk="
    }
}
```

## License

```
MIT License

Copyright (c) 2024 Marc Nguyen

Permission is hereby granted, free of charge, to any person obtaining a copy
of this software and associated documentation files (the "Software"), to deal
in the Software without restriction, including without limitation the rights
to use, copy, modify, merge, publish, distribute, sublicense, and/or sell
copies of the Software, and to permit persons to whom the Software is
furnished to do so, subject to the following conditions:

The above copyright notice and this permission notice shall be included in all
copies or substantial portions of the Software.

THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR
IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY,
FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL THE
AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER
LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING FROM,
OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN THE
SOFTWARE.
```
