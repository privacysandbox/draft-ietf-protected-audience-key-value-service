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
    ins: B. R. Hamilton
    name: Benjamin "Russ" Hamilton
    organization: Google
    email: behamilton@google.com

normative:
  CBOR: RFC8949
  CDDL: RFC8610
  JSON: RFC8259
  OHTTP: RFC9458
  HPKE: RFC9180
  GZIP: RFC1952
  Brotli: RFC7932


informative:

--- abstract

The Key Value Service provides real-time signals to ad auctions while preserving user privacy.

--- middle

# Introduction

Protected Audience is a privacy advancing API that facilitates
interest group based advertising.
Key Value Services are used by Protected Audience to provide
real-time signals to buyers and sellers during ad selection.
The Protected Audience proposal leverages Key Value
services to incorporate real-time signals into ad selection.
These services utilize User-Defined Functions (UDFs) to
provide a flexible mechanism for fetching and processing data.
While event-level logging is explicitly prohibited, the servers
may have operational side effects like monitoring to ensure
security and prevent abuse.

## Scope

This document provides a specification for the request and response message format that a client can
use to communicate with the Key Value Service as part of the client's implementation of the
Protected Audience API.

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

-   Data is transmitted over HTTPS using the `POST` method.
-   Data within the request and response is encrypted with [HPKE].
-   The core request and response data is encoded using [CBOR].

### Encryption {#encryption}

The Key Value Service uses [HPKE] with the following configuration for encryption:

-   KEM (Key encapsulation mechanisms): 0x0020 DHKEM(X25519, HKDF-SHA256), see
    {{Section 1 of HPKE}}
-   KDF (key derivation functions): 0x0001 HKDF-SHA256, see {{Section 7.2 of HPKE}}
-   AEAD (Authenticated Encryption with Associated Data): AES-256-GCM, see
    {{Section 7.3 of HPKE}}

The server is repurposing the [OHTTP] encapsulation mechanism ({{Section 4.6 of OHTTP}}), new
media types need to be defined:

-   The OHTTP request media type is `message/ad-auction-trusted-signals-request`
-   The OHTTP response media type is `message/ad-auction-trusted-signals-response`

These media types are concatenated with other fields when creating the [HPKE] encryption context.

### Message Framing {#framing}

Before encryption and after decryption, the requests and responses have the following framing:

| Byte     | 0         | 0             | 1 to 4   | 5 to Size+4       | Size+5 to end   |
| -------- | --------- | ------------- | -------- | ----------------- | --------------- |
| Bits     | 7-2       | 1-0           | \*       | \*                | \*              |
| -------- | --------- | ------------- | -------- | ----------------- | --------------- |
| Contents | Unused    | Compression   | Size     | Request Payload   | Padding         |

The request/response is framed with this 5 byte header.

The first byte is the format+compression byte. The lower 2 bits specify the format and compression ({{compression}}).
The higher 6 bits are currently unused.

The following 4 bytes are the length of the request message in network byte order.

Then the request is zero padded to a set of pre-configured lengths.
Padding is applied with sizes as multiples of 2^n KBs ranging from 0 to 2MB. So the valid response
sizes will be `[0, 128B, 256B, 512B, 1KB, 2KB, 4KB, 8KB, 16KB, 32KB, 64KB, 128KB, 256KB, 512KB, 1MB,
2MB]`.

### Format+compression byte {#compression}

| Compression | Description                    |
| :---------: | :----------------------------- |
|    0x00     | [CBOR], no compression         |
|    0x01     | [CBOR], compressed in [Brotli] |
|    0x02     | [CBOR], compressed in [GZIP]   |

For requests, the byte value is 0x00. For responses, the byte value depends on the
`acceptCompression` (see {{request-schema}}) field in the request and the server behavior.

## Core Request Data {#request}

Requests are not compressed and have a tree-like hierarchy:

-   Each request contains one or more partitions. Each partition is a collection of keys that can be
    processed together by the service without any potential privacy leakage. Keys from one interest
    group must be in the same partition. Keys from different interest groups with the same joining
    site (see https://wicg.github.io/turtledove/#joining-interest-groups) may or may not be in the same partition.
-   Each partition contains one or more key groups. Each key group has its unique attributes among
    all key groups in the partition. The attributes are represented by a list of `tags`. Besides
    tags, the key group contains a list of keys to look up.
-   Each partition has a unique id.
-   Each partition has a compression group field. Results of partitions belonging to the same
    compression group can be compressed together in the response. Different compression groups must
    be compressed separately (see {{compression-group}}).

### Encryption {#request-encryption}

The request is encrypted with [HPKE]. The request uses a repurposed [OHTTP] encapsulation format
(see {{Section 4.3 of OHTTP}} and {{Section 4.6 of OHTTP}}) with a
`message/ad-auction-trusted-signals-request` media type instead of `message/bhttp request`.

### Request Schema {#request-schema}

The request is a [CBOR] encoded message with the following [CDDL] schema:

~~~~~ cddl
request = {
    ? acceptCompression: [* tstr],
    ; must contain at least one of "none", "gzip", "brotli"
    partitions: [* partition],
    ; A list of partitions. Each must be processed independently. Accessible by UDF.
}

partition = {
    id: uint,
    ; Unique id of the partition in this request
    compressionGroupId: uint,
    ; Unique id of a compression group in this request. Only partitions belonging to the same compression group will be compressed together in the response
    ? metadata: partitionMetadata,
    arguments: [* requestArgument],
    ; One group of keys and common attributes about them
}
;Single partition object. A collection of keys that can be processed together.


partitionMetadata = {
    ? hostname: tstr,
    ; The hostname of the top-level frame calling runAdAuction
    ? experimentGroupId: tstr,
    ? slotSize: tstr,
    ; Available if trustedBiddingSignalsSlotSizeMode=slot-size. In the form of <width>,<height>
    ? allSlotsRequestedSizes: tstr,
    ; Available if trustedBiddingSignalsSlotSizeMode=all-slots-requested-sizes. In the form of <width1>,<height1>,<width2>,<height2>,...
}

requestArgument = {
    ? tags: [* tstr],
    ; List of tags describing this group's attributes
    ? data: [* tstr],
    ; List of keys to get values for
}
~~~~~

#### Available Tags

Each key group has exactly one tag from the `namespace` category.

| Tag | Description |
|---|---|
| interestGroupNames | Names of interest groups in the encompassing partition. |
| keys | “keys” is a list of trustedBiddingSignalsKeys strings. |
| renderUrls | Similarly, sellers may want to fetch information about a specific creative, e.g. the results of some out-of-band ad scanning system. This works in much the same way, with the base URL coming from the trustedScoringSignalsUrl property of the seller's auction configuration object.  |
| adComponentRenderUrls | Similar to renderUrls |


### Generating a Request

TODO

### Parsing a Request {#request-parsing}

This section describes how the Key Value Service MUST deserialize request messages from the client.

The algorithm takes as input a serialized request message from the client and a list of HPKE private
keys (along with their corresponding key IDs).

The output is either an error sent back to the client, an empty message sent back to the client, or
a request message the Key Value Service can consume along with an HPKE context.

1. Let `encrypted request` be the request received from the client.
1. Let `error_msg` be an empty string.
1. De-encapsulate and decrypt `encrypted request` by using the input private key corresponding to
   `key_id` as descripten in {{request-encryption}}, to get the decrypted message and `rctxt`.
    1. If decapsulation or decryption fails, return failure.
    1. Else, save the decrypted output as `framed request` and save `rctxt`.
1. Remove and extract the first 5 bytes from `framed request` as the `framing header` (described in
   {{framing}}), removing them from `framed request`.
    1. If the `framing header`'s `Compression` field is not supported, return failure.
1. Let `length` be equal to the `framing header`'s `Size` field.
1. If `length` is greater than the length of the remaining bytes in `framed request`, return
   failure.
1. Take the first `length` remaining bytes in `framed response` as `decodable request`, discarding
   the rest.
1. [CBOR] decode `decodable request` into the message represented in {{request-schema}}. Let this be
   `processed request`.
1. Return `processed request` and `rctxt`.

### Example Request

The [CBOR] representation consists of the following item, represented using the extended diagnostic
notation from [CDDL] appendix G:

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

## Core Response Data {#response}

The response is compressed. The compression is applied independently to each compression group. That
means, the response object mainly contains a list of compressed blobs, each for one compression
group. Each blob is for outputs of one or more partitions, sharing the same `compressionGroup` value
as specified in the request.

### Encryption {#response-encryption}

The response uses the a similar encapsulated response format to that used by [OHTTP] (see
{{Section 4.4 of OHTTP}}), but with the custom `message/ad-auction-trusted-signals-response`
media type instead of `message/bhttp response`

### Response Schema {#response-schema}

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

##### CompressionGroup {#compression-group}

The content of each `compressionGroup` is a serialized [CBOR] list of partition outputs. This object
contains actual key value results for partitions in the corresponding compression group. The
uncompressed, deserialized [CBOR] content has the following [CDDL] schema:

~~~~~ cddl
[* partitionOutput]
; Array of PartitionOutput objects

partitionOutput = {
  ? id: uint
  ; Unique id of the partition from the request
  ? keyGroupOutputs: [* keyGroupOutput]
}

keyGroupOutput = {
  tags: [* tstr]
  ; List of tags describing this key group's attributes
  ? keyValues: {
    ; At least one key-value pair if present
    * tstr => keyValue
  }
  ; One value to be returned in response for one key
  ; If a keyValues object exists, it must at least contain one key-value pair. If no key-value pair can be returned, the key group should not be in the response
}

keyValue = {
  value: tstr
}

~~~~~

#### Example Compression Group

The [CBOR] representation consists of the following item, represented
using the extended diagnostic notation from [CDDL] appendix G:

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

### Structured keys response specification

Structured keys are keys that the browser is aware of and the browser
can use the response to do
additional processing. The value of these keys must abide by the
following schema for the browser to
successfully parse them.

Note that they must be serialized to string when stored as the value.

#### InterestGroupResponse

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

Example:

~~~~~ json
{
    "priorityVector": {
        "signal1": 1,
        "signal2": 2
    },
    "updateIfOlderThanMs": 10000
}
~~~~~

### Generating a Response

This algorithm describes how the Key Value Service MAY generate a response to a request.

The input is a `payload` corresponding to {{response-schema}} and the HPKE receiver context saved in
{{request-parsing}}, `rctxt`.

The output is a `response` to be sent to a Client.

1. Let `cbor payload` equal the
   [deterministically encoded CBOR](https://www.rfc-editor.org/rfc/rfc8949.html#name-deterministically-encoded-c)
   `payload`. Return an empty `response` on CBOR encoding failure.
1. Let `compressed payload` equal the [GZIP] compressed `cbor payload`, returning an empty
   `response` on compression failure.
1. Create a framed payload, as described in {{framing}}:
    1. Create a `framing header`.
    1. Set the `framing header` `Compression` to one of 2.
    1. Set the `framing header` `Size` to the size of `compressed payload`.
    1. Let `framed payload` equal the result of prepending the framing header to
       `compressed payload`.
    2. Padding MAY be added to `framing header`.
    3. Return an empty `response` on failure of any of the previous steps.
2. Let `response` equal the result of the encryption and encapsulation of `framed payload` with
   `rctxt`, as described in {{response-encryption}}. Return an empty `response` on failure.
3. Return `response`.

### Parsing a Response

TODO

# IANA Considerations

This document has no IANA actions.

--- back

# Acknowledgments
{:numbered="false"}

TODO
