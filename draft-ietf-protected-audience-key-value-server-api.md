---
title: "Protected Audience Key Value Server APIs"
abbrev: "KV Servers APIs"
category: std

docname: draft-ietf-protected-audience-key-value-server-api-latest
submissiontype: IETF  # also: "independent", "editorial", "IAB", or "IRTF"
number:
date:
consensus: true
v: 3
# area: AREA
# workgroup: WG Working Group
keyword:
 - protected audience
 - fledge
venue:
#  group: WG
#  type: Working Group
#  mail: WG@example.com
#  arch: https://example.com/WG
  github: "privacysandbox/draft-ietf-protected-audience-key-value-service"
  latest: "https://privacysandbox.github.io/draft-ietf-protected-audience-key-value-service/draft-ietf-protected-audience-key-value-server-api.html"

author:
 -
    fullname: "Peiwen Hu"
    organization: Google
    email: "peiwenhu@google.com"
 -
    fullname: "Benjamin Russ Hamilton"
    organization: Google
    email:  "behamilton@google.com"

normative:
  CBOR: RFC8949
  CDDL: RFC8610

informative:


--- abstract

TODO Abstract


--- middle

# Introduction

TODO

# Conventions and Definitions

{::boilerplate bcp14-tagged}

## Core data

Core request and response data structures are all in {{CBOR}}.

The schema below is defined following the {{CDDL}}

### Request

*   Each request contains one or more partitions. Each partition is a collection of keys that can be processed together by the service without any potential privacy leakage. Keys from one interest group must be in the same partition. Keys from different interest groups with the same joining site may or may not be in the same partition, so the server User Defined Functions should not make any assumptions based on that.
*   Each partition contains one or more key groups. Each key group has its unique attributes among all key groups in the partition. The attributes are represented by a list of “Tags”. Besides tags, the key group contains a list of keys to look up.
*   Each partition has a unique id.
*   Each partition has a compression group field. Results of partitions belonging to the same compression group can be compressed together in the response. Different compression groups must be compressed separately. See more details below. The expected use case by the client is that interest groups from the same joining origin and owner can be in the same compression group.

TODO


### Schema of the request

~~~ cddl
request = {
    ? acceptCompression: [* tstr],
    ; must contain at least one of none, gzip, brotli
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
~~~

#### Available Tags


| Tag category | Category description | Tag | Description |
| Namespace| Each key group has exactly one tag from this category.| interestGroupNames | Names of interest groups in the encompassing partition. |
| | | keys | “keys” is a list of trustedBiddingSignalsKeys strings. |
| | | renderUrls | Similarly, sellers may want to fetch information about a specific creative, e.g. the results of some out-of-band ad scanning system. This works in much the same way, with the base URL coming from the trustedScoringSignalsUrl property of the seller's auction configuration object. |
| | | adComponentRenderUrls | |

TODO: see if the above can be improved

Example trusted bidding signals request from Chrome:
The cbor representation consists of the following item, represented using the
extended diagnostic notation from {{CDDL}} appendix G:

~~~ cbor-diag
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
~~~

### Schema of the Response

#### Response

The response is compressed. Due to security and privacy reasons the compression is applied independently to each compression group. That means, The response object mainly contains a list of compressed blobs, each for one compression group. Each blob is for outputs of one or more partitions, sharing the same compressionGroup value as specified in the request.

~~~ cddl
response = {
  ? compressionGroups : [* compressionGroup]
}

compressionGroup = {
  ? compressionGroupId: uint,
  ? ttl_ms: uint,
  ; Adtech-specified TTL for client-side caching. In milliseconds. Unset means no caching.
  ? content: bstrs
  ; Compressed CBOR binary string using the algorithm specified in the request
  ; For details see compressed response content schema below.
}
~~~

##### CompressionGroup

The content of each compressed blob is a CBOR list of partition outputs. This object contains actual key value results for partitions in the corresponding compression group.

~~~ cddl
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


~~~

Example:

~~~ cbor-diag
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
~~~

### Structured keys response specification

Structured keys are keys that the browser is aware of and the browser can use the response to do additional processing. The value of these keys must abide by the following schema for the browser to successfully parse them.

Note that they must be serialized to string when stored as the value.

#### InterestGroupResponse

The schema below is defined following the spec by https://json-schema.org/
For values for keys from the `interestGroupNames` namespace, they must conform to the following schema, prior to being serialized to string:

~~~ json
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
~~~

Example:

~~~ json
{
  "priorityVector": {
    "signal1": 1,
    "signal2": 2
  },
  "updateIfOlderThanMs": 10000
}
~~~

# IANA Considerations

This document has no IANA actions.

--- back

# Acknowledgments
{:numbered="false"}

TODO acknowledge.
