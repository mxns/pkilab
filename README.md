# pki

## Build

```
docker build -t pki
```

## Run

#### Generate certificates for root CA, intermediate CA, host and client:

```
docker run pki > certificates.asc
```

#### Extract PKCS12 archive for host and client from generated file:

```
sed "3q;d" certificates.asc | cut -d'|' -f6 | base64 -d > host.p12    # password: serverpass
sed "4q;d" certificates.asc | cut -d'|' -f6 | base64 -d > client.p12  # password: clientpass
```
