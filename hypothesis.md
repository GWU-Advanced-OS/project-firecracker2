# Hypothesis
* Firecracker is a lightweight VMM specialized for serverless workloads. Due to the fact that device drivers are not needed, the vmm can be programmed with a minimal approach. This decreases boot time and reduces the size of TCB increasing security.
* Firecracker is best suited to be integrated with applications that has an event driven API due to its faster boot time and automated scaling. 
* Frontend: Invoke traffic arrives at the frontend via the Invoke REST API
* Worker Manager: selects one of the warm microVM in the ready but not utilized vm pool to forward workloads to directly. Stick-routes events to as few workers as possible.
* The host facing REST API aims to allow multiple languages to interact with Firecracker. Worker managers provides abstraction to find available warm idling slots/VMs. Scaling up and down is abstracted from the customer. Building up the Virtual Environment around existing worker slots allows for easy integration with lambda functions.
* They provide higher security than Linux containers as each workload has its own isolated kernel.
* Their minimalist approach increases the speed of the boot time as well. 
* Security principles: Strong isolation - every function runs in it's own VM. The TCB is very small and this minimalistic approach enchances the security of the system by reducing the attack area.
* Pre configuring the microVMs give them rather quick boot times which is a necessary improvement on virtualization to reduce latency. Sticky routing events to VMs allows the frontend to send traffic directly to the workers instead of going through the worker manager.
* Simple concept of simplifying the current infrastructure that Linux and other open source projects like kubernetes provides. Limited by the fact that they are attempting to provide a general service that fully implements the Linux syscalls. Other implementations such as microkernels, unikernels, such as that implemented in EdgeOS can still provide strong isloation but with even faster performance. Difficult for users to implements coordination and communication between workloads/events as each process is given its dedicated VM.
