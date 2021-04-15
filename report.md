# :notebook: Summary

### :nerd_face: What is Firecracker? 
AWS lambda provides clients to run code based on incoming requests or events. This provides customers with scalability without having to manage or provision servers. Due to the economies of scale, it is important for multinency to be supported. Multitenancy is the provisioning and sharing of workloads across servers, in this case lambda functions. This provides a distinct economic advantage through greater utilization of hardware resources. However, this creates some distinct challenges such as ensuring isolation between workloads and clients as well as quick startup time in response to quick changes in traffic demands.

Firecracker was introduced to specifically address these challenges. Firecracker is an open source virtual machine monitor that is specialized for server less workloads. Implemented with a minimal feature set, Firecracker only contains 50k lines of Rust which is 96% fewer than QEMU. Device drivers such as GPU, USB, displays and speakers could be removed as they are not required in the context of server less computing provided by lambda.



### :mag_right: Why does Firecracker exists? 

The diagram below describes the previous architecture that supported AWS lambda. Understanding the limitations and tradeoffs in this design will help provide a good inclination as to why Firecracker was deemed necessary and ultimately developed.

![image](https://user-images.githubusercontent.com/54540257/113560094-2b5fc480-959e-11eb-9a37-10362f12a3da.png)

**Linux containers** provided isolation between multiple functions.  
**Virtual machines** provided isolation between multiple clients.

This system provided **benefits** of:
* **Isolation**: These two mechanisms provided multiple functions to be able to be run on the same hardware while being protected from privilege escalation and information disclosure.
* **Overhead and density** Multiple functions could be deployed on the same resources. However, density can be limited as the resources associated with each client is already being consumed before any workloads have been deployed and can perform any useful work.
* Defense in depth as workloads from different clients are separated in both virtual machines as well as containers.

**Trade offs** of this system included: 
* **Soft allocation** is where hardware resources is not over committed and each function only consumes the resources it needs and not it is entitled to. Difficulty in provisioning sufficient resources for each virtual machine to support the multiple functions as well as ensuring sufficient management and efficient utilization of resources across different virtual machines. This design could lead to waste if the demand for the workloads for a client does not meet the amount of resources that have been provisioned. This makes ensuring density in the system a challenge. 
* **Compatibility** involves supporting unmodified code (in this case Linux libraries). Containers rely on a single operating system creating a tradeoff between security and code compatibility. Containers can improve security by limiting syscalls at the risk of breaking code that requires those syscalls.
* **Fast Switching** VM startup time range in the region of seconds. This is particularly impactful in lambda as deployments of functions are small and thus relative overhead is much larger. Booting smaller lightweight kernels are not a option in this scenario due to the requirement compatibility aforementioned
* **Performance** of workloads must be consistent. Although, containers provide isolation through namespaces, they must still share the same resources. Access to these resources will have are limited using the Linux functionality cgroups if there is contention for resources between separate containers.
* Hypervisors and VMM must communicate with the underlying kernel and thus adding a significant amount to the TCB. 

### :goal_net: Firecracker's goals.

Firecracker was developed to target these challenges while attempting to satisfy properties of Isolation, Overhead and density, Performance, Compatability, Fast Switching and lastly Soft Allocation.


# :bow_and_arrow: Target Domain

### :money_with_wings: Where is it valuable?

To understand why Firecracker is valuable, we first need to understand the **needs of Lambda and what services it is attempting to provide**. AWS Lambda scales applications in response to incoming events. Processes trigger workloads individually and needs to support request scaling from a few per day to thousands per second. [[2]](#References) Lambda also promises code to not require infrastructure in order to be managed and will scale up and down automatically.

Therefore it is important that Firecracker has a low boot latency to ensure startup time is not exposed to its customers. One of the factors that impacts boot time are probing for device drivers. Therefore, kernel features and modules that are not necessary for a typical server less and container workloads can be excluded from the kernel configuration. Removing unnecessary emulated drivers ensures faster boot up time as well as decreasing the lines of code of Firecracker. This decreases the size of the trusted code base thus increasing confidence of the system security.

One firecracker process runs per MicroVM. This achieves a few of the goals required of the system. Single process VMs provide a simple model for security isolation. Overhead and density as well as soft allocation is ensured. This may seem a bit counter intuitive at first. Starting process in a virtualized environment has inherent overhead in memory usage related to booting the dedicated kernel. However, due to the minimal guest kernel configuration supported, the relative overhead in this system is low. Therefore, by having a single process per VM, Firecracker VMs can be pre configured to consume only the amount of memory and CPU resources required of that process, ensuring that resources are not over committed. 

### :no_good: Where is it not a good fit?

Firecracker is more suited to be integrated with applications that has an event driven API. Long running an memory intensive workloads, would not be able to benefit greatly from Firecracker main selling point of being able to scale up and down.

# 	:scroll: References

[1] https://www.usenix.org/system/files/nsdi20-paper-agache.pdf  
[2] https://aws.amazon.com/lambda/
