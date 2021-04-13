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

# Jack

## What is Firecracker? What are it's goals and why does it exist?

* “Firecracker is an open-source virtualization technology that is purpose-built for 
  creating and managing secure, multi-tenant container and function-based services that provide serverless operational models.”

* Firecracker uses minimalist, Linux-based microVMs using containers. 
  These microVMs increase system security and client isolation while also utilizing the increase in speed and resource efficiency that containers provide.

* Firecracker implements a minimalist approach to microVMs which means that only the essential devices and functionality is used and all non-essential parts are removed (minimize the memory footprint). 
  This minimal design allows for an increase in speed as well as security because it reduces the number of places malicious partiescan exploit. 

* Firecracker aims to provide safe and efficient machines and services that allow multiple clients to run on the same device isolated from each other.

* Features [2]
* (1) Firecracker can safely run workloads from different customers on the same machine.
* (2) Customers can create microVMs with any combination of vCPU and memory to match their application requirements.
* (3) Firecracker microVMs can oversubscribe host CPU and memory. The degree of oversubscription is controlled by customers, who may factor in workload correlation and load in order to ensure smooth host system operation.
* (4) With a microVM configured with a minimal Linux kernel, single-core CPU, and 128 MiB of RAM, Firecracker supports a steady mutation rate of 5 microVMs per host core per second 
      (e.g., one can create 180 microVMs per second on a host with 36 physical cores).
* (5) The number of Firecracker microVMs running simultaneously on a host is limited only by the availability of hardware resources.
* (6) Each microVM exposes a host-facing API (REST) via an in-process HTTP server.
* (7) Each microVM provides guest-facing access to host-configured metadata via the /mmds API.  

## System Modules

* Firecracker contains many small modules written in Rust.
    - Each module is small and contains only the necessary information needed to complete a task.

* I think that the modules in Firecracker use the hierarchical approach. Each module has its own API and interface
  that other modules can utilize to perform different tasks.
    - TODO: Talk about interface properties (orthogonality, idempotency, etc.)

### The Jailer Process

* The jailer process is responsible for starting a new Firecracker process. The jailer initializes system resources that require
  higher priviledges and executes into the Firecracker binary which spawns a new Firecracker process which runs in the VM as an
  unpriviledged process.

* When the jailer is invoked, there are many parameters passed in. These include:
    - A unique `id` which represents a VM
    - An `exec_file` which is the file path to the Firecracker binary that the jailer will execute.
    - A `uid` and `gid` that the jailer will switch to as it executes the binary.
    - ... for a more in-depth look into all of the parameters, see [3].

* When the jailer is invoked, an ArgParser object is created which contains all of the specified arguments and their characteristics.
  This can be seen here [4].

* Once the jailer has created a new ArgParser object, a new environment is created with the arguments. [5]

* The Env struct can be seen below:
```rust
    pub struct Env {
        id: String,
        chroot_dir: PathBuf,
        exec_file_path: PathBuf,
        uid: u32,
        gid: u32,
        netns: Option<String>,
        daemonize: bool,
        start_time_us: u64,
        start_time_cpu_us: u64,
        extra_args: Vec<String>,
        cgroups: Vec<Cgroup>,
    }
```

* Once the Env struct is populated with the arguments and everything is set up, the new Env can be run,
  which will run the exec file and start a new Firecracker process. [6] 

### Dumbo

* Dumbo is a HTTP/TCP/IPv4 network stack that handles guest HTTP requests sent to the configured mmds address.

* Dumbo is disabled by default but can be turned on using the `allow_mmds_requests` parameter.

* "Firecracker only offers virtio-net paravirtualized devices to guests. Drivers running on guest OS use
  ring buffers in shared memory to communicate with the device model for sending or receiving frames."
    - Implementation of these ring buffers can be found at [7]

* Each guest device is associated with a TAP device on the host. [8]
    - Frames sent from guest get written to the TAP fd. [8 Line 174]
    - Frames read from TAP fd are sent to the guest. [8 Line 168]

* Each network device can have one Dumbo stack. Each time a frame is sent from the guest, it is examined
  to see if it should be processed by Dumbo instead of being written to TAP.

* Every time that space becomes available in the ring buffers to send frames to the guest, it first checks Dumbo,
  and then goes back to getting frames from the TAP file descriptor.

### Event Manager



## What are the core technologies and how are they composed?

* The main Firecracker code base is written Rust. (~50k LoC)
* The integration tests are written in Python.
* Firecracker uses a Docker container to standardize the build process and to compose everything together

## Firecracker Security Properties

![image](https://raw.githubusercontent.com/firecracker-microvm/firecracker/main/docs/images/firecracker_threat_containment.png)

* Firecracker has strong isolation and containment by having several nested layers all with different levels of trust.
  On top of the different zones, they are separated by different barriers that enforce different aspects of Firecracker security.
  All of these trusted layers and security barriers combine to enforce strong defense in depth.

* Each client is completely isolated from the other clients running on the host. So a breach in one does not spread to other microVM's.

* Firecracker utilizes a minimalist design minimizes the attack-surface (by minimizing the memory footprint) that malicious parties can exploit.

* Small TCB -> Firecracker is ~50k LoC which is 96% less than QEMU. 
  Furthermore, Firecracker's minimalist design removes all unnecessary resources from the system
  which further minimizes Firecracker's TCB.

* This relatively small TCB also touches on the Economy of Mechanism or K.I.S.S.
  This principle discusses the correlation between system complexity and the existence of bugs.
    - More edge-cases -> harder to test
    - Fewer bugs / minimize complexity -> less likely to be compromised and easier to fix.
* Since Firecracker has a relatively small TCB and is relatively simple, this could impact the number
  of bugs in the system and it can make it easier to fix bugs when they come up.

* [1] https://www.usenix.org/system/files/nsdi20-paper-agache.pdf
* [2] https://github.com/firecracker-microvm/firecracker/blob/master/docs/design.md
* [3] https://github.com/firecracker-microvm/firecracker/blob/master/docs/jailer.md
* [4] https://github.com/firecracker-microvm/firecracker/blob/master/src/jailer/src/main.rs#L221-L278
* [5] https://github.com/firecracker-microvm/firecracker/blob/master/src/jailer/src/main.rs#L367-L377
* [6] https://github.com/firecracker-microvm/firecracker/blob/master/src/jailer/src/env.rs#L368-L464
* [7] https://github.com/firecracker-microvm/firecracker/blob/master/src/virtio_gen/src/virtio_ring.rs
* [8] https://github.com/firecracker-microvm/firecracker/blob/main/src/devices/src/virtio/net/tap.rs





