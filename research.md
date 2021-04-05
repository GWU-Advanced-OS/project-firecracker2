# Questions

* Summarize the project, what it's goals are, and why it exists

        Firecracker is a lightweight virtual machine monitor designed with the goal of achieving the security benefits of virtualization without having to make the traditional sacrifice in performance. The project is being developed as a part of AWS and supports AWS Lambda serverless functions[1].

* What is the target domain of the system? Where is it valuable and where is it not a good fit? 

        Firecracker is being designed to support AWS lambda:[1]
        - IoT
        - Mobile/Web apps
        - request/response/event driven services
        - real time streaming/data processing
        - automation

* “Firecracker is an open-source virtualization technology that is purpose-built for creating and managing secure, multi-tenant container and function-based services that provide serverless operational models.”

* Firecracker uses minimalist, Linux-based microVMs using containers. These microVMs increase system security and client isolation while also utilizing the increase in speed and resource efficiency that containers provide.

* Firecracker implements a minimalist approach to microVMs which means that only the essential devices and functionality is used and all non-essential parts are removed (minimize the memory footprint). This minimal design allows for an increase in speed as well as security because it reduces the number of places malicious partiescan exploit. 

* Firecracker aims to provide safe and efficient machines and services that allow multiple clients to run on the same device isolated from each other.

* Features (From Github “design.md”)
(1) Firecracker can safely run workloads from different customers on the same machine.
(2) Customers can create microVMs with any combination of vCPU and memory to match their application requirements.
(3) Firecracker microVMs can oversubscribe host CPU and memory. The degree of oversubscription is controlled by customers, who may factor in workload correlation and load in order to ensure smooth host system operation.
(4) With a microVM configured with a minimal Linux kernel, single-core CPU, and 128 MiB of RAM, Firecracker supports a steady mutation rate of 5 microVMs per host core per second 
(e.g., one can create 180 microVMs per second on a host with 36 physical cores).
(5) The number of Firecracker microVMs running simultaneously on a host is limited only by the availability of hardware resources.
(6) Each microVM exposes a host-facing API (REST) via an in-process HTTP server.
(7) Each microVM provides guest-facing access to host-configured metadata via the /mmds API.  

[1] https://www.usenix.org/system/files/nsdi20-paper-agache.pdf
