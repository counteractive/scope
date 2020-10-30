# SCOPE: STIX Custom Objects, Proposals, and Extensions

A repository and namespace for STIX custom objects and extensions, as well as proposals for how they could be used.  Because we see opportunities to expand the _scope_ of STIX's influence in infosec, naturally.

Built for discussion and evaluation, to try to find any devils in the details. Please open an issue or submit a pull request if you're interested in contributing.

**Caveat:** This is alpha content, not (yet) intended for production use.  However, all customizations should be [compliant with the STIX 2.1 spec](https://docs.oasis-open.org/cti/stix/v2.1/csprd01/stix-v2.1-csprd01.html#_Toc16070825), so it shouldn't break anything to try it out.

## Goals

1. Support wider adoption of STIX data abstractions in detection and response.  
    
    A small expansion of observable types will go a long way towards addressing the applicability of STIX to detection and response use-cases.

1. Support improved [data source documentation](https://github.com/mitre-attack/attack-datasources) and relationships in MITRE ATT&CK.

    Describing object _types_ (vs. just instances) as first-class STIX domain objects lets us attach useful metadata (like data sources!) and empowers more flexible relationships.

1. Stay within the STIX spec and keep customizations minimal to reduce standards proliferation.


## Background

The Structured Threat Information Expression (STIX) is an open specification for sharing cyber threat intelligence (CTI) maintained by the [OASIS](https://www.oasis-open.org/) CTI technical committee (TC).  STIX provides consistent abstractions and a prescriptive exchange format for cyber threat activity, and it's the canonical format for the popular [MITRE ATT&CK](https://attack.mitre.org/) framework.

We love STIX, but we've run into two limitations:

1. **STIX v2.1 chose to limit its catalog of observable object types, omitting certain types useful for detection and response.**  

    A STIX working document captured this comment by [Rich Struse](https://www.oasis-open.org/people/distinguished-contributor/richard-struse):

    > "while I understand that organizations want and need to track specific assets that were impacted by an event, I find it hard to imagine the general-purpose use-case where organizations are sharing such info widely. As such, it seems out of scope for a CTI exchange format."

    We appreciate the desire to manage the scope of the STIX project, but we respectfully disagree.  

    1. Security operations, digital forensics, and incident response frequently require sharing information across organizational boundaries.  We commonly share between departments, sister organizations, regulators, attorneys, law enforcement, vendors, customers, and more.  It just tends to be _ad hoc_, governed by whatever tools or procedures happen to be in place. Lots of word documents and pdfs.
    1. STIX has features for controlling how information should be shared (_e.g._, [TLP](https://www.cisa.gov/tlp)): it's not exclusively designed for sharing information "widely."
    1. Attacks are often launched from victims' compromised systems, so the distinction between "friendly assets" and "attacker infrastructure" is already pretty blurry.
    1. It leads to arbitrary distinctions (_e.g._, having a `user-account` observable in scope, but the system a `user-account` _uses_ out of scope).
    1. Parallel efforts for describing "friendly" or "internal" observables would have to solve problems STIX already solved ... along with compatibility with STIX itself!

    **Bottom line:** we think STIX has a lot to offer beyond just CTI, particularly in the realm of detection and response, and a few custom objects would vastly increase its usefulness without unduly compromising concision.

    Fortunately STIX v2.1 supports [custom objects and extensions](https://docs.oasis-open.org/cti/stix/v2.1/cs01/stix-v2.1-cs01.html#_3wlhv7hxh2en), and this project respects those constraints, making it compatible with existing spec.

1. **There's no obvious way to capture data about _object types themselves_ (as opposed to _instances_ of types) within STIX.**  That is, types are not objects to which you can add "static" or "prototypical" data, nor can you refer to object types directly in relationships.

    MITRE ATT&CK's recent efforts around data sources show how it would be nice, for example, to have a STIX representation of the `process` type to which we could attach useful data (e.g., where to find concrete evidence about `process`es on a system).  
    
    Also, having _types_ as first-class STIX objects makes relationships much more powerful.  You could say things like "`tool` _t_ creates `process` objects with properties of a certain kind."

    With custom objects we can make this happen too!

## Custom Observable Types

### System

- System (`x-scope-system`)
    - Physical System Extension (`x-scope-physical-ext`), _e.g._, laptop, desktop, smartphone
    - Virtual System Extension (`x-scope-virtual-ext`), _e.g._, vm, container
    - Datastore System Extension (`x-scope-datastore-ext`), _e.g._, database, wiki, s3
    - Appliance System Extension (`x-scope-appliance-ext`), _e.g._, load balancer, wifi gateway, WAF
    - Platform System Extension (`x-scope-platform-ext`), _e.g._, cloud email tenant, CRM instance

The concept of a "system" (_a.k.a._, host, endpoint, asset) is ubiquitous, and has an intuitive definition, something like "a logically distinct combination of hardware and software."  A system is where most observables are in fact observed: `file`, `process`, `user-account`, _etc._, are observed on systems.

Except STIX doesn't have a type for them.  CybOX used to (called "System"), ECS does (called "Host"), and it's floated as a possibility for STIX v2.2+ in the working documents, but it's not in the current spec.

Another way to think of a system is as anything supporting sessions (see below), but regardless of the formal definition, it's a prerequisite to making STIX more relevant to detection and response.  We think it'll help the CTI use-case too.

We propose bringing it back as a new, inclusive `system` type with extensions to capture the fact that systems aren't just physical desktop boxes anymore.  See the details and comments in [system/x-scope-system.yml](./objects/system/x-scope-system.yml)

### Session

- Session (`x-scope-session`)

A session is any period of interaction between an account and a system (see above).  ECS has an open RFC that captures their variety well: sessions can be local, remote, network, or more, and on any type of system (virtual, physical, appliance, _etc._).

They're characterized by an account, system, start time, and end time, though in the simplest case these times may be the same (say, for a single REST call).  Also, one or the other times may be unknown.

Current STIX fields like `user-account`'s first and last login times don't give sufficient granularity to describe activity in the context of detection and response, and they don't capture the reality that user accounts can access many systems.

Bringing a `session` type into the mix provides a great tool for sharing information about **timelines**, which are critical for detection, response, and CTI alike.

### API

- API (`x-scope-api`)

Application programming interfaces (APIs) are central to many adversary techniques, but there's currently no way to describe them in STIX.  Like with `system`, there was such a type in CybOX, but it was culled.

We recommend resurrecting it, if only for its applicability to ATT&CK.  It might be a bit tricky to get the details right, but the juice will be worth the squeeze.

For example, when discussing ATT&CK `attack-pattern`s like [process injection](https://attack.mitre.org/techniques/T1055/) and its sub-techniques, it's helpful to refer to specific Windows APIs and API calls.

Like `system`, `api` would benefit from an updated definition to include the breadth of modern API types, from OS system calls to RPC to REST.

## Custom Domain Objects

### STIX Type Object

- STIX Type (`x-scope-stix-type`)

This gets a little meta, but bear with us 😃: the idea is to capture details about STIX object _types_ as concrete STIX _objects_, because it's only STIX objects that can contain real data and be the target of references.

Put another way: currently the details of the `process` type live in a word document and a non-normative json schema.  They're not STIX data.  This would allow us to capture that in a STIX object itself, _a la_:

```json
{
    "type": "x-scope-stix-type",
    "id": "x-scope-stix-type--GUID-FOR-PROCESS-TYPE",
    "name": "process",
    "schema": { /*json schema from https://github.com/oasis-open/cti-stix2-json-schemas/blob/master/schemas/observables/process.json */ },
    "external_references": [ /* refs */ ]
    /* other fields */
}
```

This provides some benefits:

1. **You can store data that applies to all objects of that type.**  For you programmers, think static members in C++/Java or prototype properties in javascript.

    Improving MITRE ATT&CK's data sources led to the idea of storing them in SCO types themselves.  It'd be useful to describe what Windows event logs would help us populate a `process` observable, for example.  With a first-class `stix-type` object, we could add this data under the `external_references` field of the `stix-type` object for the `process` SCO (or to a custom `evidence_locations` field, or whatever).

1. **Relationships (SROs) could then refer to types rather than just instances.**

    It can be useful to describe the relationships of one SCO type to another.  Some of these, like a `user-account` creating a `process`, are **embedded relationships** captured by a `_ref` field in the object.  These are well-suited to `external_references` on the SCO type as noted above.  In pseudo-code:

    ```json
    {
        "type": "x-scope-stix-type",
        "id": "x-scope-stix-type--GUID-FOR-PROCESS-TYPE",
        "name": "process",
        "external_references": [
            {/*info about windows EID 4688 and how it supports filling the creator_user_ref field (the user-account -> process embedded relationship)*/}
        ]
    }
    ```

    Others, like a `process` setting a `windows-registry-key`, don't have embedded `_ref`s.  These could be described with a new relationship object (SRO). With a first-class `stix-type`, we can create an SRO that captures this, and attach `external_references` or other fields to that SRO:

    ```json
    {
        "type": "relationship",
        "id": "relationship--GUID",
        "relationship_type": "set",
        "source_ref": "x-scope-stix-type--GUID-FOR-PROCESS-TYPE",
        "target_ref": "x-scope-stix-type--GUID-FOR-REGISTRY-KEY-TYPE",
        "external_references": [
            {/*info about sysmon EID 13 and how it links process info to registry key activity (the process -> windows-registry-key non-embedded relationship)*/}
        ]
    }
    ```
    
    Take another example unrelated to logs: let's say we wanted to express "the `attack-pattern` [Create or Modify System Process: Windows Service (T1543.003)](https://attack.mitre.org/techniques/T1543/003/) creates `process` observables. The [current model](https://docs.oasis-open.org/cti/stix/v2.1/csprd01/stix-v2.1-csprd01.html#_Toc16070618) doesn't allow relationships between `attack-pattern`s and observable types, but with a `stix-type` object you could express it easily.

1. You can transmit the STIX specification as STIX data.  It's like having a compiler written in the language itself.

## Usage

The proposed objects are stored in the [objects](./objects/) directory as yaml files.  These can be transformed into a reasonable facsimile of the STIX spec format using the node script in the [render](./render/) folder.  

Forgive the spaghetti-code ejs template - this is just to prove you can build a similar looking spec from yaml, which would be easier to serialize into the `stix-type` objects described above.  And would be easier to collaborate on via github ...

```bash
# needs nodejs
$ cd ./render
$ npm install

# user-account.yml is a built-in, included for testing:
./render/render.js render/template.ejs objects/user-account/user-account.yml > user-account.html

# custom types are stubs for now:
./render/render.js render/template.ejs objects/system/x-scope-system.yml > system.html
```

## Prior Art

1. MITRE ATT&CK [data source initiative](https://github.com/mitre-attack/attack-datasources) ([discussion](https://github.com/mitre-attack/attack-datasources/issues/2), blog [part 1](https://medium.com/mitre-attack/defining-attack-data-sources-part-i-4c39e581454f), blog [part 2](https://medium.com/mitre-attack/defining-attack-data-sources-part-ii-1fc98738ba5b))
1. MITRE [Cyber Analytics Repository](https://car.mitre.org/) (CAR)
1. [CyBOX](https://cyboxproject.github.io/releases/2.1/), an archived project that was worked into STIX SCOs.
1. [Elastic Common Schema](https://www.elastic.co/guide/en/ecs/current/ecs-field-reference.html) (ECS), used primarily to add normalized fields to logging data.

## License

Copyright 2020 Counteractive Security

Licensed under the Apache License, Version 2.0 (the "License"); you may not use this file except in compliance with the License. You may obtain a copy of the License in the [LICENSE](./LICENSE) file or at:

http://www.apache.org/licenses/LICENSE-2.0

Unless required by applicable law or agreed to in writing, software distributed under the License is distributed on an "AS IS" BASIS, WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied. See the License for the specific language governing permissions and limitations under the License.

