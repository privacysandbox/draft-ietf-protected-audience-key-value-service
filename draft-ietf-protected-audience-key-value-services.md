---
coding: utf-8

title: Protected Audience Key Value Services
abbrev: "KV Services"
docname: draft-ietf-protected-audience-key-value-services-latest
category: std
submissionType: IETF

area: TBD
workgroup: TBD
keyword: Internet-Draft

ipr: trust200902

stand_alone: yes
pi: [toc, sortrefs, symrefs]

author:
 -
    name: Peiwen Hu
    organization: Google
    email: peiwenhu@google.com
 -
    name: Tianyang Xu
    organization: Google
    email: xtlsheep@google.com
 -
    name: Lusa Zhan
    organization: Google
    email: lusazhan@google.com

normative:
  HTTPS: RFC2818
  CBOR: RFC8949
  CDDL: RFC8610
  JSON: RFC8259
  OHTTP: RFC9458
  HPKE: RFC9180
  GZIP: RFC1952
  Brotli: RFC7932


informative:

--- abstract

This document specifies a protocol for a Key Value Service that can serve data with low latency
and no side effects. The data served can be used by clients for advertisement selection and the
lack of side effects can be used to advance user privacy.

--- middle

# Introduction

[Protected Audience](https://wicg.github.io/turtledove/) is a privacy advancing API that serves
remarketing and custom audiences use cases.
Key Value Services are trusted execution environment (TEE) based Key/Value databases that can be used to store
and integrate real-time data into Protected Audiences Auctions. The Protected
Audience proposal leverages Key Value Services to incorporate real-time information
into ad selection for both buyers and sellers. This information could be used,
for example, to add budgeting data about each ad. These services provide a
flexible mechanism for fetching and processing data. While event-level logging
is explicitly prohibited, the services may have operational side effects like
monitoring to ensure security and prevent abuse.

## Scope

This document provides a specification for the request and response message format that a client can
use to communicate with the Key Value Service as part of the client's implementation of the
[Protected Audience API](https://wicg.github.io/turtledove/).

This document does not describe distribution of private keys to the Key Value Service.

## Terminology

The key words "MUST", "MUST NOT", "REQUIRED", "SHALL", "SHALL NOT", "SHOULD", "SHOULD NOT",
"RECOMMENDED", "NOT RECOMMENDED", "MAY", and "OPTIONAL" in this document are to be interpreted as
described in BCP 14 {{!RFC2119}} {{!RFC8174}} when, and only when, they appear in all capitals, as
shown here.

The key word "client" is to be interpreted as an implementation of this document that creates
Requests ({{request}}) and consumes Responses ({{response}}). The key phrase "Key Value Service" is
to be interpreted as an implementation of this document that consumes Requests and creates
Responses.

# Message Format Specifications {#format}

## Overview

To understand this document, it is important to know that the
communication between the client and the remote services uses a
request-response message exchange pattern.
On a high level, these request and response messages adhere to the following communication protocol:

-   Data is transmitted over [HTTPS] using the `POST` method.
-   Data within the request and response is encrypted with [HPKE].
-   The core request and response data is encoded using [CBOR].

### Encryption {#encryption}

The Key Value Service uses [HPKE] with the following configuration for encryption:

-   HPKE KEM ID (Key encapsulation mechanisms):
    0x0020 DHKEM(X25519, HKDF-SHA256), see {{Section 1 of HPKE}}
-   HPKE KDF ID (key derivation functions): 0x0001 HKDF-SHA256, see {{Section 7.2 of HPKE}}
-   HPKE AEAD ID (Authenticated Encryption with Associated Data): AES-256-GCM, see
    {{Section 7.3 of HPKE}}

### Message Framing {#framing}

Before encryption and after decryption, the requests and responses have the following framing:

| Byte     | 0         | 0             | 1 to 4   | 5 to Size+4       | Size+5 to end   |
| -------- | --------- | ------------- | -------- | ----------------- | --------------- |
| Bits     | 7-2       | 1-0           | \*       | \*                | \*              |
| -------- | --------- | ------------- | -------- | ----------------- | --------------- |
| Contents | Unused    | Compression   | Size     | Payload           | Padding         |

The request/response is framed with this 5 byte header.

The first byte is the format+compression byte. The lower 2 bits specify the format and compression ({{compression}}).
The higher 6 bits are currently unused.

The following 4 bytes are the length of the request message in network byte order.

Padding is applied differently for request and response and will be discussed in the respective
sections.

### Format+compression byte {#compression}

| Compression | Description                    |
| :---------: | :----------------------------- |
|    0x00     | [CBOR], no compression         |
|    0x01     | [CBOR], compressed in [Brotli] |
|    0x02     | [CBOR], compressed in [GZIP]   |
|    0x03     | Reserved                       |

Requests are always uncompressed so the Format+compression byte is 0x00.

For responses, the byte value depends on the `acceptCompression` field
(see {{request-schema}}) in the request and the server behavior.

## Request Data {#request}

Requests are not compressed and have a tree-like hierarchy:

-   Each request contains one or more partitions. Each partition is a collection of keys that SHALL
    be processed together by the service. Keys from separate partitions MUST NOT be processed together by the service.
-   Each partition contains one or more key groups.
    Each key group contains a list of `tags` set by the client.
    Each key group contains a list of keys to be looked up in the service's internal datastore.
-   Each partition has a unique identifier.
    This allows the client to match the request partition with the corresponding
    `partitionOutput` (see {{compression-group}}) in the response.
-   Each partition has a compression group field.
    Results of partitions belonging to the same compression group can be compressed together
    in the response.
    The responses for different compression groups will be compressed separately in the response
    (see {{compression-group}}). Compressing the different groups separately avoids leaking the
    similarity of responses for different groups.

### Encryption {#request-encryption}

The request is encrypted with [HPKE] with the configuration specified at {{encryption}}.

The request uses a similar encapsulated message format to that used by [OHTTP].

~~~~~
Encapsulated Request {
  Key Identifier (8),
  HPKE KEM ID (16),
  HPKE KDF ID (16),
  HPKE AEAD ID (16),
  Encapsulated KEM Shared Secret (8 * Nenc),
  HPKE-Protected Request (..),
}
~~~~~

The service uses a repurposed [OHTTP] encapsulation mechanism (see {{Section 4.6 of OHTTP}})
for which it defines a new `message/ad-auction-trusted-signals-request` media type.

Request encapsulation is similar to {{Section 4.3 of OHTTP}}, only with the
`message/ad-auction-trusted-signals-request` media type:

1. Construct a message header (`hdr`) by concatenating the values of the
   `Key Identifier`, `HPKE KEM ID`, `HPKE KDF ID`, and `HPKE AEAD ID` in network
   byte order.
2. Build a sequence of bytes (`info`) by concatenating the ASCII-encoded string
   "message/ad-auction-trusted-signals-request", a zero byte, and `hdr`.
3. Create a sending HPKE context by invoking `SetupBaseS()`
   ([Section 5.1.1](https://rfc-editor.org/rfc/rfc9180#section-5.1.1) of [HPKE])
   with the public key of the receiver `pkR` and `info`. This yields the context
   `sctxt` and an encapsulation key `enc`.
4. Encrypt `request` by invoking the `Seal()` method on `sctxt`
   ([Section 5.2](https://rfc-editor.org/rfc/rfc9180#section-5.2) of [HPKE])
   with empty associated data `aad`, yielding ciphertext `ct`.
5. Concatenate the values of `hdr`, `enc`, and `ct`.

In pseudocode, this procedure is as follows:

~~~~~
hdr = concat(encode(1, key_id),
             encode(2, kem_id),
             encode(2, kdf_id),
             encode(2, aead_id))
info = concat(encode_str("message/ad-auction-trusted-signals-request"),
              encode(1, 0),
              hdr)
enc, sctxt = SetupBaseS(pkR, info)
ct = sctxt.Seal("", request)
enc_request = concat(hdr, enc, ct)
~~~~~

The client needs to save `sctxt` for decryption of the response (see {{response-encryption}}).

A Key Value Service endpoint decrypts this encapsulated message in a
similar manner to [OHTTP]
[Section 4.3](https://www.rfc-editor.org/rfc/rfc9458#name-encapsulation-of-requests),
or more explicitly as follows:

1. Parse `enc_request` into `key_id`, `kem_id`, `kdf_id`, `aead_id`,
   `enc`, and `ct`.
2. Find the matching HPKE private key, `skR`, corresponding to `key_id`. If
   there is no matching key, return an error.
3. Build a sequence of bytes (`info`) by concatenating the ASCII-encoded string
   "message/ad-auction-trusted-signals-request"; a zero byte;
   `key_id` as an 8-bit integer; plus
   `kem_id`, `kdf_id`, and `aead_id` as three 16-bit integers.
4. Create a receiving HPKE context, `rctxt`, by invoking `SetupBaseR()`
   ([Section 5.1.1](https://rfc-editor.org/rfc/rfc9180#section-5.1.1) of [HPKE])
   with `skR`, `enc`, and `info`.
5. Decrypt `ct` by invoking the `Open()` method on `rctxt`
   ([Section 5.2](https://rfc-editor.org/rfc/rfc9180#section-5.2) of [HPKE]),
   with an empty associated data `aad`, yielding `request` and returning an
   error on failure.

In pseudocode, this procedure is as follows:

~~~~~
key_id, kem_id, kdf_id, aead_id, enc, ct = parse(enc_request)
if version != 0 then return error
info = concat(encode_str("message/ad-auction-trusted-signals-request"),
              encode(1, 0),
              encode(1, key_id),
              encode(2, kem_id),
              encode(2, kdf_id),
              encode(2, aead_id))
rctxt = SetupBaseR(enc, skR, info)
request, error = rctxt.Open("", ct)
~~~~~

Key Value Services retain the HPKE context, `rctxt`, so that it can
encapsulate a response.

### Framing and Padding {#request-framing}

The plaintext request message uses the framing described in {{framing}}.

Messages MAY be zero padded.

### Request Schema {#request-schema}

The request is a [CBOR] encoded message with the following [CDDL] schema:

~~~~~ cddl

compressionType = "none" / "gzip" / "brotli"

request = {
    ? acceptCompression: [1* compressionType],
    ; A list of supported response compression algorithms; must contain at least one of "none", "gzip", "brotli"
    ? metadata: requestMetadata,
    ; Metadata that applies for the request as a whole.
    partitions: [1* partition],
    ; A list of partitions. Each must be processed independently. Accessible by user-defined functions.
}

requestMetadata = {
    ? hostname: tstr,
    ; The hostname of the top-level frame calling runAdAuction
}

partition = {
    id: uint,
    ; Unique id of the partition in this request. Used by responses to refer to request partitions.
    compressionGroupId: uint,
    ; Unique id of a compression group in this request. Only partitions belonging to the same compression group will be compressed together in the response
    ? metadata: partitionMetadata,
    ; Partition-level metadata.
    arguments: [* requestArgument],
    ; One group of keys and common attributes about them
}
;Single partition object. A collection of keys that can be processed together.

partitionMetadata = {
    ? experimentGroupId: tstr,
    ? slotSize: tstr,
    ? allSlotsRequestedSizes: tstr,
}

requestArgument = {
    ? tags: [1* tstr],
    ; List of tags describing this group's attributes. These MAY be picked from the list of available tags in {{tags}}.
    ? data: [* tstr],
    ; List of keys to get values for.
}
~~~~~

#### Available Tags {#tags}

Each key group is expected to have exactly one tag from the following list:

| Tag | Description |
|---|---|
| interestGroupNames | Names of interest groups in the encompassing partition. |
| keys | "keys" represent the keys to be looked up from the service's internal datastore. |
| renderUrls | "renderUrls" represent URLs for advertisements to be looked up from the service's internal datastore. |
| adComponentRenderUrls | "adComponentRenderUrls" represent component URLs for advertisements to be looked up from the service's internal datastore. |

### Generating a Request {#request-generate}

This section describes how the client MAY form and serialize request messages in order to fetch values from the Trusted Key Value server.

This algorithm takes as input an [HPKE] `public key` and its associated `key id`, a `metadata` map for global configuration, where both keys and values are strings, and a `compression groups` list, each of which is a map, from key `"partitions"` to value `partitions` as a list of maps.

The output is an [HPKE] ciphertext encrypted `request` and a context `request context`.

1. Let `request map` be an empty map.
1. Let `partitions` be an empty array.
1. For each `group` in `compression groups`:
  1. For each `partition` in `compression groups["partitions"]:
    1. Let `p` be an empty map.
    1. Set `p["compressionGroupId"]` to `group[compressionGroupId"]`.
    1. Set `p["id"]` to `partition["id"]`.
    1. Let `arguments` be an empty array.
    1. For each `key` → `value` in `partition`:
      1. If `key` equals "metadata":
        1. Set `p["metadata"]` to `partition["metadata"].
      1. Otherwise:
        1. Let `argument` be an empty map.
        1. Set `argument["tags"]` to `key`.
        1. Set `argument["data"]` to `data`.
        1. Insert `argument` into `arguments`.
    1. Set `p["arguments"]` to `arguments`.
    1. Insert `p` into `partitions`.
1. Set `request map["metadata"]` to `metadata`.
1. Set `request map["partitions"]` to `partitions`.
1. Set `request map["acceptCompression"]` to `["none", "gzip"]`.
1. [CBOR] encode `request map` to `payload`.
1. Create a `framed payload`, as described in {{framing}}:
    1. Create a {{framing}} header `framing header`.
    1. Set `framing header`'s `Compression` to 1.
    1. Set `framing header`'s `Size` to the size of `payload`.
    1. Set `framed payload` to the concatenation of `framing header` and `payload`.
    1. Padding MAY be added to `framed payload`.
    1. Return an empty `request` on failure of any of the previous steps.
1. [HPKE] encrypt `framed payload` using `public key` and `key id` as in {{request-encryption}} to get the [HPKE] encrypted ciphertext `request` and [HPKE] encryption context `request context`.
1. Return`request` and `request context`.

### Parsing a Request {#request-parsing}

This section describes how the Key Value Service MUST deserialize request messages from the client.

The algorithm takes as input a serialized request message from the client and a list of HPKE private
keys (along with their corresponding key IDs).

The output is either an error sent back to the client, an empty message sent back to the client, or
a request message the Key Value Service can consume along with an HPKE context.

1. Let `encrypted request` be the request received from the client.
1. Let `error_msg` be an empty string.
1. Decrypt `encrypted request` by using the input private key corresponding to
   `key_id` as described in {{request-encryption}}, to get the decrypted message and `rctxt`.
    1. If decryption fails, return failure.
    2. Else, save the decrypted output as `framed request` and save `rctxt`.
2. Remove and extract the first 5 bytes from `framed request` as the `framing header` (described in
   {{framing}}), removing them from `framed request`.
    1. If the `framing header`'s `Compression` field is not `0x00` (no compression), return failure.
3. Let `length` be equal to the `framing header`'s `Size` field.
4. If `length` is greater than the length of the remaining bytes in `framed request`, return
   failure.
5. Take the first `length` remaining bytes in `framed response` as `decodable request`, discarding
   the rest.
6. [CBOR] decode `decodable request` into the message represented in {{request-schema}}. Let this be
   `processed request`.
    1. If decoding fails, return failure.
7. If no `partitions` are present, return failure.
8. Set `compressionGroupMap` to an empty map.
9. For each `partition` in `partitions`:
   1. Let `partitionIds` be an empty list.
   2. Set `partitionIds` to `compressionGroupMap[compression group id]` if the map entry exists.
   3. Append `partition["id"]` to `partitionIds`.
   4. Set `compressionGroupMap[compression group id]` to `partitionIds`.
10. Return `processed request`, `compressionGroupMap`, and `rctxt`.

## Response Data {#response}

The response is an HPKE encrypted message sent as a Response to a Request, containing a framed top-level
CBOR encoded payload that itself can contain multiple, possibly compressed, CBOR encoded messages.

### Encryption {#response-encryption}

The response uses a similar encapsulated response format to that used by
[OHTTP].

~~~~~
Encapsulated Response {
  Nonce (8 * max(Nn, Nk)),
  AEAD-Protected Response (..),
}
~~~~~


The response uses the a similar encapsulated response format to that used by [OHTTP] (see
{{Section 4.4 of OHTTP}}), but with the custom `message/ad-auction-trusted-signals-response`
media type instead of `message/bhttp response`:

1. Export a secret (`secret`) from `context`, using the string
   "message/ad-auction-trusted-signals-response" as the `exporter_context` parameter to
   `context.Export`; see [Section 5.3](https://www.rfc-editor.org/rfc/rfc9180.html#name-secret-export)
   of [HPKE]. The length of this secret is `max(Nn, Nk)`, where `Nn` and `Nk` are
   the length of the AEAD key and nonce that are associated with `context`.
2. Generate a random value of length `max(Nn, Nk)` bytes, called `response_nonce`.
3. Extract a pseudorandom key (`prk`) using the `Extract` function provided by
   the KDF algorithm associated with context. The `ikm` input to this function
   is `secret`; the `salt` input is the concatenation of `enc` (from
  `enc_request`) and `response_nonce`.
1. Use the `Expand` function provided by the same KDF to create an AEAD key,
   `key`, of length `Nk` -- the length of the keys used by the AEAD associated
   with `context`. Generating `aead_key` uses a label of "key".
2. Use the same `Expand` function to create a nonce, `nonce`, of length `Nn`
   -- the length of the nonce used by the AEAD. Generating `aead_nonce` uses a
  label of "nonce".
1. Encrypt `response`, passing the AEAD function `Seal` the values of `aead_key`,
   `aead_nonce`, an empty `aad`, and a `pt` input of `response`. This yields `ct`.
2. Concatenate `response_nonce` and `ct`, yielding an Encapsulated Response,
   `enc_response`. Note that `response_nonce` is of fixed length, so there is no
  ambiguity in parsing either `response_nonce` or `ct`.

In pseudocode, this procedure is as follows:

~~~~~
secret = context.Export("message/ad-auction-trusted-signals-response", max(Nn, Nk))
response_nonce = random(max(Nn, Nk))
salt = concat(enc, response_nonce)
prk = Extract(salt, secret)
aead_key = Expand(prk, "key", Nk)
aead_nonce = Expand(prk, "nonce", Nn)
ct = Seal(aead_key, aead_nonce, "", response)
enc_response = concat(response_nonce, ct)
~~~~~

Clients decrypt an Encapsulated Response by reversing this process. That is,
Clients first parse `enc_response` into `response_nonce` and `ct`. Then, they
follow the same process to derive values for `aead_key` and `aead_nonce`, using
their sending HPKE context, `sctxt`, as the HPKE context, `context`.

The Client uses these values to decrypt `ct` using the AEAD function `Open`.
Decrypting might produce an error, as follows:

~~~~~
response, error = Open(aead_key, aead_nonce, "", ct)
~~~~~

### Framing and Padding {#response-framing}

The plaintext response message uses the framing described in {{framing}}.

Padding is applied with sizes as multiples of 2^n KBs ranging from 0 to 2MB. So the valid response
sizes will be `[0, 128B, 256B, 512B, 1KB, 2KB, 4KB, 8KB, 16KB, 32KB, 64KB, 128KB, 256KB, 512KB, 1MB,
2MB]`.

If the response message is larger than 2MB, an error is returned.

### Response Schema {#response-schema}

The response MAY be compressed. The compression is applied independently to each compression group. That
means, the response object mainly contains a list of compressed blobs, each for one compression
group. Each blob is for outputs of one or more partitions, sharing the same `compressionGroup` value
as specified in the request.

The response is a [CBOR] encoded message with the following [CDDL] schema:

~~~~~ cddl
response = {
  ? compressionGroups : [* compressionGroup]
}

compressionGroup = {
  ? compressionGroupId: uint,
  ; Partition outputs with the same `compressionGroupId` specified in the request
  ; are compressed together.
  ? ttl_ms: uint,
  ; Adtech-specified TTL for client-side caching. In milliseconds. Unset means no caching.
  ? content: bstrs
  ; Compressed CBOR binary string using the algorithm specified in the request
  ; For details see compressed response content schema below.
}
~~~~~

#### CompressionGroup {#compression-group}

The content of each `compressionGroup` is a serialized [CBOR] list of partition outputs. This object
contains actual key value results for partitions in the corresponding compression group. The
uncompressed, deserialized [CBOR] content has the following [CDDL] schema:

~~~~~ cddl
compressionGroup = [* partitionOutput]
; Array of PartitionOutput objects

partitionOutput = {
  id: uint
  ; Unique id of the partition from the request
  ? keyGroupOutputs: [* keyGroupOutput]
}

keyGroupOutput = {
  tags: [* tstr]
  ; List of tags describing this key group's attributes
  ? keyValues: {
    ; At least one key-value pair if present
    * tstr => tstr
  }
  ; One value to be returned in response for one key
  ; If a keyValues object exists, it must at least contain one key-value pair. If no key-value pair can be returned, the key group should not be in the response
}
~~~~~

### Structured keys response specification

Structured keys are keys that the client is aware of and the client
can use the response to do
additional processing. The value of these keys must abide by the
following schema for the client to
successfully parse them.

Note that they must be serialized to string when stored as the value.

#### InterestGroupResponse {#interest-group-response}

The schema below is defined following the spec by
https://json-schema.org. For values for keys
from the `interestGroupNames` namespace, they must conform to the
following schema, prior to being
serialized to string.

~~~~~ json
{
    "title": "tkv.response.v2.InterestGroupResponse",
    "description": "Format for value of keys in groups tagged 'interestGroupNames'",
    "type": "object",
    "additionalProperties": false,
    "properties": {
        "priorityVector": {
            "type": "object",
            "patternProperties": {
                ".*": {
                    "description": "signals",
                    "type": "number"
                }
            }
        },
        "updateIfOlderThanMs": {
            "description": "This optional field specifies that the interest group should be updated if the interest group hasn't been joined or updated in a duration of time exceeding `updateIfOlderThanMs` milliseconds. Updates that ended in failure, either parse or network failure, are not considered to increment the last update or join time. An `updateIfOlderThanMs` that's less than 10 minutes will be clamped to 10 minutes.",
            "type": "unsigned integer"
        }
    }
}
~~~~~

### Generating a Response

The Key Value Service runs user-defined functions (UDF) as part of request handling
and response generation. User-Defined Functions (UDFs) are custom functions implemented by adtech that encapsulate adtech-specific business logic for processing partitions within the Key Value Service. These functions are executed within a sandboxed environment without network or disk access, but have read access to data loaded into the Key Value Service.
Each UDF receives a single `partition` object from the client request as input. The output of a UDF is a `partitionOutput` object that contains the results of processing the partition.

The below algorithm describes how the Key Value Service MAY generate a response to a request.

The input is a list of [deterministically encoded CBOR](https://www.rfc-editor.org/rfc/rfc8949.html#name-deterministically-encoded-c) `partitionOutputs` in {{response-schema}} as well as
the `compressionGroupMap` and the HPKE receiver, `rctxt`, context saved in {{request-parsing}}.
Assume that this response is to a request that includes `gzip` in `acceptCompression`.

The output is a `response` to be sent to a Client.

1. Create an empty `payload` object, corresponding to {{response-schema}}.
2. Set `compression groups` to an empty list.
3. Set `partitionOutputMap` to an empty map.
4. For each `partitionOutput` in the list of `partitionOutputs`:
   1. Set `partitionOutputMap[partitionOutput["id"]]` to `partitionOutput`.
5. For each (`compression group id`, `partition ids`) in `compressionGroupMap`:
   1. Create an empty `compression group` object, corresponding to {{compression-group}}.
   2. Set `cbor partitions array` to an empty CBOR array.
   3. For each `partition id` in `partition ids`:
      1. Set `partition output` to `partitionOutputMap[partition id]`.
         1. On failure to find the `partition id`, continue.
      2. Append `partition output` to `cbor partitions array`.
   4. Set `cbor serialized payload` to the CBOR serialized `cbor partitions array`.
      1. On serialization failure, continue.
   5. Set `compression group content` to the [GZIP] compressed `cbor serialized payload`.
      1. On failure, continue.
   6. Set `compression group["compressionGroupId"]` to `compression group id`
   7. Set `compression group["content"]` to `compression group content`.
   8. Add `compression group` to `compression groups`.
6. Set `payload["compressionGroups"]` to `compression groups`.
7. Create a framed payload, as described in {{framing}}:
    1. Create a `framing header`.
    2. Set the `framing header` `Compression` to one of 2.
    3. Set the `framing header` `Size` to the size of `compressed payload`.
    4. Let `framed payload` equal the result of prepending the framing header to
       `payload`.
    5. Padding MAY be added to `framed payload`.
    6. Return an empty `response` on failure of any of the previous steps.
8. Let `response` equal the result of the encryption and encapsulation of `framed payload` with
   `rctxt`, as described in {{response-encryption}}. Return an empty `response` on failure.
9.  Return `response`.

### Parsing a Response (#response-parsing)

This section describes how a conforming Client MUST parse and validate a response from a Trusted Key Value service. 

It takes as input the `request context` returned from {{request-generate}} in addition to the `encrypted response`.

The output is a `result` map, where the keys are strings, and the values are maps with both keys and values as strings.

1. Use `request context` as the context to decrypt `encrypted response` and obtain `framed response`, returning failure if decryption fails.
1. Remove and extract the first 5 bytes from `framed response` as the framing header (described in {{framing}}), removing them from `framed response`.
1. If `framing header`'s `Compression` field is not 0 or 2, return failure.
1. Let `length` be equal to the `framing header`'s `Size` field.
1. If `length` is greater than the length of the remaining bytes in `framed response`, return failure.
1. Take the first `length` remaining bytes in `framed response` as `serialized response`, discarding the rest.
1. [CBOR] decode the `serialized response` into `response`, returning failure if decoding fails.
1. If `response` is not a map, return failure.
1. If `response["compressionGroups"]` does not exist, or is not an array, return failure.
1. Let `results` be an empty array.
1. For each `group` in `response["compressionGroups"]`:
    1. If `group` is not a map, return failure.
    1. If `group["content"]` does not exist, return failure.
    1. Set `serialized content` to the result of decompressing `group["content"]` according to the compression algorithm specified in the `framing header`'s `Compression` field, returning failure if decompression fails.
    1. [CBOR] decode the `serialized content` into `content`, returning failure if decoding fails.
    1. If `content` is not an array, return failure.
    1. For each `partition` in `content`:
        1. If `partition` is not a map, return failure.
        1. If `partition["keyGroupOutputs"]` does not exist, or is not an array, return failure.
        1. Let `result` be an empty map.
        1. For each `output` in `partition["keyGroupOutputs"]`:
            1. If `output` is not a map, return failure.
            1. If `output["tags"]` does not exist, or is not an array, return failure.
            1. If `output["keyValues"]` does not exist or is not a map, return failure.
            1. Let `key value` be an empty map.
            1. For each `key` → `value` in `output["keyValues"]`:
                1. If `key` is not a string, return failure.
                1. If `value` is not a map, return failure.
                1. If `value["value"]` does not exist, or is not a string, return failure.
                1. Set `key value[key]` to `value["value"]`.
            1. Set `result[output["tags"]]` to `key value`.
        1. If `partition["dataVersion"]` exists, Set `result["dataVersion"]` to `partition["dataVersion"]`.
        1. Set `result["compressionGroupId"]` to `group["compressionGroupId"]`.
        1. Set `result["id"]` to `partition["id"]`.
        1. Append `result` to `results`.
1. Return `results`.

# Security Considerations

The Key Values Service is run by adtechs as service operators and relies on [HPKE] to encrypt communication between the client
and the Key Value Service endpoint.
This protects the confidentiality and integrity of requests and responses, particularly between the point of HTTPS/TLS termination and the TEE. By encrypting messages at this stage, [HPKE]
prevents service operators from reading or modifying them in transit.
While HPKE encryption protects message contents, the size of encrypted messages
is still observable. This could potentially be exploited as a side-channel
to leak information. Implementations MAY employ padding techniques described
in this document to mitigate this risk.

To achieve specific privacy goals, clients can break up the request into
separate partitions. Partitions prevent one interest group from influencing the response to another one. This isolation ensures that information remains compartmentalized and prevents unintended interference between interest groups.

A cross-site tracking risk exists where an adtech could attempt to link a user’s identity across different websites. An interest group owner could join a user to interest groups on multiple sites and observe changes in the request’s overall compression ratio. This protocol mitigates this risk by compressing interest groups for different sites separately.

An implementation should ensure that public keys used for encryption
are obtained from a trusted source to prevent impersonation and unauthorized access.
Private keys should be stored securely to prevent compromise.

# IANA Considerations

TODO

--- back

# Appendix

## Example Request

An example of the [CBOR] representation for {{request-schema}} using the extended diagnostic notation
from [CDDL] [Appendix G](https://datatracker.ietf.org/doc/html/rfc8610#appendix-G):

~~~~~ cbor-diag
{
  "acceptCompression": [
    "none",
    "gzip"
  ],
  "partitions": [
    {
      "id": 0,
      "compressionGroupId": 0,
      "metadata": {
        "hostname": "example.com",
        "experimentGroupId": "12345",
        "slotSize": "100,200",
      },
      "arguments": [
        {
          "tags": [
            "interestGroupNames"
          ],
          "data": [
            "InterestGroup1"
          ]
        },
        {
          "tags": [
            "keys"
          ],
          "data": [
            "keyAfromInterestGroup1",
            "keyBfromInterestGroup1"
          ]
        }
      ]
    },
    {
      "id": 1,
      "compressionGroupId": 0,
      "arguments": [
        {
          "tags": [
            "interestGroupNames"
          ],
          "data": [
            "InterestGroup2",
            "InterestGroup3"
          ]
        },
        {
          "tags": [
            "keys"
          ],
          "data": [
            "keyMfromInterestGroup2",
            "keyNfromInterestGroup3"
          ]
        }
      ]
    }
  ]
}
~~~~~

## Example Compression Group

An example of the [CBOR] representation for {{compression-group}} using the extended diagnostic notation
from [CDDL] [Appendix G](https://datatracker.ietf.org/doc/html/rfc8610#appendix-G):

~~~~~ cbor-diag
[
  {
    "id": 0,
    "keyGroupOutputs": [
      {
        "tags": [
          "interestGroupNames"
        ],
        "keyValues": {
          "InterestGroup1": {
            "value": "{\"priorityVector\":{\"signal1\":1}}"
          }
        }
      },
      {
        "tags": [
          "keys"
        ],
        "keyValues": {
          "keyAfromInterestGroup1": {
            "value": "valueForA"
          },
          "keyBfromInterestGroup1": {
            "value":"[\"value1ForB\",\"value2ForB\"]"
          }
        }
      }
    ]
  }
]
~~~~~

## Example

An example of {{interest-group-response}}.

~~~~~ json
{
    "priorityVector": {
        "aSignal": 1,
        "anotherSignal": 2
    },
    "updateIfOlderThanMs": 10000
}
~~~~~


# Acknowledgments
{:numbered="false"}

TODO
