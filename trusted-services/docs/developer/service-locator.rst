Service Locator
===============

The service locator model provides clients of trusted services with a common interface for locating service instances and
establishing RPC sessions with service endpoints.  By using the service locator, application code is decoupled from the details
of where services are deployed.  Use of the service locator is entirely optional for client applications.  Different deployments
of *libts* provide implementations of the service locator API that are suitable for different environments.  The trusted
services project uses *libts* to decouple test code from the services under test.  This enables tests to be reused for testing
on different platforms with different distributions of services.  The same flexibility may be exploited when writing
applications that use trusted services.

Service Locator Model
---------------------

The following class diagram illustrates the service locator model:

.. uml:: uml/ServiceLocatorClassDiagram.puml

The model takes inspiration from microservices architectures where there is a similar need to decouple clients from service
location.  In the model, classes have the following roles:

Class service_locator
'''''''''''''''''''''

The service_locator is responsible for locating service provider instances and returning a service_context object to allow a
client to establish RPC sessions with the located service endpoint.  A service instance is requested by a client using a service
name.  The service name uniquely identifies a service instance, independent of where the service provider is located.  The
service_locator is a singleton and forms the common interface for locating trusted services.

Class service_context
'''''''''''''''''''''

A service_context object represents a located service and enables a service client to establish RPC sessions with the service.
A concrete service_context will provide open and close methods that manage RPC session setup and teardown.

Class rpc_caller
''''''''''''''''

An rpc_caller provides methods for making remote calls associated with a service endpoint.  An rpc_caller object represents an
instance of an RPC session.

Locating Service Instances
--------------------------

The location of service instances is likely to vary between deployments.  Many factors influence where a service instance is
deployed and the method needed to locate it.  e.g.:

    - The type of processing environment in which a service instance is deployed. e.g. service could be deployed in a secure
      partition, as a TA or in a secure enclave.
    - Whether a service instance is co-located with other services instances in the same processing environment or whether a
      separate environment instance is used per service instance.
    - For Linux user-space clients, the kernel driver model used for messaging influences how a service is located and the type
      of messaging interface used for RPC requests.

Because of the wide variability in service deployment options, the Trusted Services framework supports the following:

    - *Location independent service names* - a naming convention for identifying service instances, wherever they are located.
      By using a location independent service name, a client is decoupled from the actual location of a service instance
      (similar to a DNS names).  A concrete service locator is responsible for resolving the location independent service name.
    - *Service location strategies* - to accommodate the likely variability, an extensible framework for alternative service
      location strategies is provided.

Service Names
'''''''''''''

Location Independent Service Names
``````````````````````````````````

Because of the potential variability in where service instances are deployed, a naming convention that allows a service instance
to be identified, independent of its location, is useful.  By using a location independent service name, coupling between a
client application and any particular service deployment can be avoided.  Use of the Service Locator API and location
independent service names allows client applications to be portable across different platforms.

The service instance naming convention uses a URN type string to uniquely identify a particular instance of a class of service.
To provide extensibility, a naming authority is included in the name.  This allows anyone with a domain name to define their own
unique service names.  Core service names are defined under the *trustedfirmware.org* authority.  The general structure of a
service name is as follows::

    urn:sn:<authority>:<service>.<version>:<instance>

    The 'urn' prefix should be dropped when service names are used in context.
    The version field is optional.

The naming convention includes a version number, separated from the <service> field by a '.' character. Beyond the '.', any
version numbering scheme may be used.  This will potentially be useful for delegating version compatibility decisions to a
service locator.  It is preferable for a client to specify a service name that includes a version number as this will
potentially allow a service locator to:

    - Locate a compatible service instance.  For example, a service provider may expose multiple RPC call endpoints to handle
      different protocol versions.  A service locator may resolve the name to the compatible RPC endpoint, based on the version
      string requested by the client.
    - Fail gracefully if no compatible version is found.

Some example service names::

    sn:trustedfirmware.org:crypto.1.0.4:0
    sn:trustedfirmware.org:secure-storage.1.3.11:1
    sn:trustedfirmware.org:tpm.2.0:0

Location Specific Service Names
```````````````````````````````

To enable a client to be able to specify location specific service names, it should also be possible to use names that express a
location specific identifier such as a partition UUID.  While use of location specific services names creates a coupling between
the client and details of the service deployment, their use may be important in the following cases:

    - Where there is no well-known mapping between a location independent service name and a location specific identifier.
    - Where the client needs to be specific e.g. for tests that target a specific service deployment.

Location specific service names use the same structure as location independent services names but with a technology specific
authority field.  The following is an example of a service name that identifies a service instance that is deployed in a secure
partition::

    sn:ffa:d9df52d5-16a2-4bb2-9aa4-d26d3b84e8c0:0

    The instance field qualified a particular SP instance from the discovered set.

Service Location Strategies
'''''''''''''''''''''''''''

The method used by the service locator to resolve a service name to a service instance will depend on the environment in which a
client is running and where service instances are located.  Services will need to be located by any client of a trusted service.
There are typically two classes of trusted service client:

    - A user-space application.
    - Another trusted service, running in a secure processing environment.

Different methods for locating service instances in different environments are illustrated in the following examples:

Locating a Service from Linux User-space
````````````````````````````````````````

Depending on the kernel driver model used, the example methods for locating service instances from Linux user-space are:

    1. Service instances are represented by device nodes e.g. /dev/tpm0.  The service locator will simply map the <service>
       portion of the services name to the base device name and the <instance> to the device node instance.
    2. A service instance is hosted by a TEE as a TA.  The TEE will provide a discovery mechanism that will allow a TA type and
       instance to be identified.  The service locator will need to map the service name to the TEE specific naming scheme.
    3. A special device that provides messaging provides a method for discovery. e.g. an FF-A driver supports partition
       discovery.
    4. A device is used for remote messaging to a separate microcontroller.  There is a well-known protocol for endpoint
       discovery using the messaging layer.

Locating a Service from another Trusted Service
```````````````````````````````````````````````

Where a trusted service uses another trusted service, it is likely that both service instances will be running in the same
security domain e.g. both running in secure partitions within the secure world.  Where a single service instance is deployed per
secure partition, the client service will use the following strategy to locate the service provider:

    1. The service name is mapped to the well known UUID for the class of SP that hosts the service provider.
    2. FF-A partition discovery is used to find all SPs that match the requested UUID.
    3. The service instance portion of the service name is used to match the partition ID when selecting the target SP from the
       list of discovered SPs.

Extending the Service Locator Model
```````````````````````````````````

To accommodate the need to support alternative location strategies, the Service Locator model can be extended to use a set of
concrete strategy objects to implement different methods of locating a service instance.  The set of strategies used will be
different for different client environments.  The following class diagram illustrates how the model can be extended.

.. uml:: uml/ServiceLocationStrategyClassDiagram.puml

--------------

*Copyright (c) 2020-2021, Arm Limited and Contributors. All rights reserved.*

SPDX-License-Identifier: BSD-3-Clause
