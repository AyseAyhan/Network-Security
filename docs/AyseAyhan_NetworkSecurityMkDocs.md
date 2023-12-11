> ![](media/image1.png){width="2.61825678040245in"
> height="2.6310411198600177in"}

**ESKISEHIR OSMANGAZI UNIVERSITY COMPUTER ENGINEERING**

**NETWORK SECURITY WITH OPEN SOURCE TOOLS COURSE PROJECT:**

**NETWORK SECURITY STRATEGIES AND PRACTICES**

**-NETWORK SECURITY APPLICATIONS AND TOOLS-**

**DECEMBER 13, 2023**

**Course Instructor: Cem Ibrahim ARI**

**Prepared by: Ayse Ayhan-152120201058**

**CONTENTS**

**I.) INTRODUCTION
............................................................................................................1**

**II.) FIREWALLS
...................................................................................................................1**

> **2.1.) Operation Logic of Security
> Firewalls...................................................................4**
>
> **2.2.) Firewall Types
> .............................................................................................\...\...\.....5**

**III.) IDS/IPS (Intrusion Detection and Prevention
Systems)....................................\.....8**

**IV.) ANTIVIRUS SOFTWARE
..............................................................................................9**

> **4.1.) Security Updates
....................................................................................................11**

> **4.2.) Antivirus Protection Selection
> Criteria:...............................................................11**

**V.) CRYPTOGRAPHY AND ENCRYPTION TOOLS
............................................................11**

**5.1.) The Role of Cryptography in
Cybersecurity.........................................................12**

> **5.2.) The Strength of a Cipher in Cryptography
> ..........................................................12**
>
> **5.3.) Exemplary Cryptographic Applications
> ...............................................................13**
>
> **5.4.) Cryptographic
> Techniques.....................................................................................13**

**VI.) OTHER NETWORK SECURITY APPLICATIONS AND TOOLS
....................................14**

> **6.1.) Network Access Control (NAC)
> .............................................................................14**
>
> **6.2.) Web Application Security
> ......................................................................................15**
>
> **6.3.) Mobile Device Management (MDM)
> ...................................................................17**

> **6.4.) Virtual Private Networks
(VPN).............................................................................19**

**VII.)
CONCLUSION.............................................................................................................20**

**VIII.)
REFERENCES..............................................................................................................21**

**I.INTRODUCTION**

Today, the rapid advancement of technology and the spread of
digitalization causes network security to become an indispensable
necessity for individuals, companies and states. In this context,
stakeholders facing various cyber threats resort to various network
security applications and tools to ensure the security of information,
systems and communication networks. This report, which will cover basic
network security issues from a broad perspective, will not be limited
only to firewalls, but will also focus on important elements such as
antivirus software, cryptography and encryption and other network
security applications. This review will contribute to our understanding
of various strategies and methods in the field of network security,
contributing to the awareness of individuals, companies, and governments
to effectively protect their digital assets.

**II. FIREWALLS**

Firewalls can be viewed as gated boundaries or gateways that govern the
movement of permitted and prohibited web activity within a private
network. This phrase comes from the concept of physical walls that slow
the spread of fire until the fire department can extinguish it. In
contrast, network security firewalls are for managing web traffic and
are generally intended to slow the spread of web threats.

Firewalls create choke points to route web traffic, which are then
reviewed and acted upon through a series of programmed parameters. Some
firewalls also monitor traffic and connections in audit logs to refer to
what is allowed or blocked.

![](media/image2.jpeg){width="5.316666666666666in"
height="3.5444444444444443in"}Firewalls are typically used to seal off
the boundaries of a private network or its host devices. Therefore,
firewalls are a security tool within the broader category of user access
control. These barriers are typically installed in two locations:
private computers or user computers on the network and the other
endpoints themselves.

**2.1. Operation Logic of Security Firewalls**

The functioning of a security firewall involves making decisions on
which network traffic is allowed to pass through and which traffic is
deemed unsafe. Essentially, it works by distinguishing between the good
and the bad or the trustworthy and the untrustworthy.

Security firewalls are designed to secure private networks and the
endpoint devices within them, known as network hosts. Network hosts are
devices that communicate with other hosts in the network. They send and
receive data between internal networks and also between external
networks.

Computers and other endpoint devices use networks to access the internet
and each other. However, the internet is divided into \'subnets\' for
security and privacy purposes. **The primary subnet segments are as
follows:**

External Public Networks are typically referred to as the general/global
Internet or various extranets.

Internal Private Networks define a home network, corporate intranets,
and other \'closed\' networks.

Perimeter Networks elaborate on border networks consisting of fortress
host computers, separated with reinforced security, ready to withstand
external attacks. Serving as a secure buffer between internal and
external networks, they can also be used to host any externally facing
services provided by the internal network (such as servers for web,
email, FTP, etc.). They are more secure than external networks but less
secure than internal networks. They may not always be present in simpler
networks like home networks but are often used in corporate or national
intranets.

Screened routers are private network gateway computers placed on a
network to partition it into sections. They are known as network-level
home security firewalls. The two most common segment models are screened
host firewall and screened subnet firewall:

Screened host firewalls use a single screened router between external
and internal networks, creating two subnets for this model.

Screened subnet firewalls use two screened routers, one known as an
access router between external and perimeter networks, and the other
known as a partition router between perimeter and internal networks.
This creates three subnets in sequence. Both the perimeter and the host
machines themselves can host a security firewall. To achieve this, it is
placed between a single computer and its connection to a private
network.

Network security firewalls involve the implementation of one or more
security firewalls between external networks and internal private
networks. They regulate incoming and outgoing network traffic by
separating global external networks like the global internet from
internal networks like home Wi-Fi networks, corporate intranets, or
national intranets. Network security firewalls can take the form of any
of the following types of tools: dedicated hardware, software, or
virtual.

Host-based firewalls or software firewalls include the use of security
firewalls on individual user devices and other private network endpoints
as a barrier within the network. These devices or host computers receive
customized regulation of incoming and outgoing traffic for specific
computer applications. Host-based firewalls can function as an operating
system service or an endpoint security application on local devices. By
filtering based on protocols like HTTP and other network protocols, they
can delve into the depths of web traffic and allow control over what
content comes from where and what content reaches your machine.

While a network security firewall requires configuration for a broad
connection scope, a host-based firewall can be tailored to fit the needs
of each machine. However, customizing host-based firewalls requires more
effort, meaning they are ideal for a comprehensive control solution for
network-based security firewalls. Nonetheless, using both firewalls
simultaneously in both places is ideal for a multi-layered security
system.

A firewall, by utilizing pre-established or dynamically learned rules,
filters network traffic and determines whether to allow or reject
connection attempts. These rules define how the firewall regulates the
flow of web traffic through your private network and individual computer
devices. **All firewalls can apply filters based on various combinations
of the following factors:**

Source: The location initiating the connection attempt.

Destination: The location where the connection attempt is made.

Content: What a tested connection is attempting to send.

Packet Protocols: The language a tested connection is speaking to carry
its message. TCP/IP protocols, primarily used for communication between
computers on the internet and intranet/subnets, are prevalent among host
computers.

Application Protocols: Common protocols such as HTTP, Telnet, FTP, DNS,
and SSH.

Source and destination information is conveyed using internet protocol
(IP) addresses and ports. IP addresses are unique device identifiers for
each computer. Ports represent a sublevel of any source and destination
host device, similar to offices serving specific purposes for everyone
in a larger building. Ports are usually assigned specific purposes;
therefore, using unusual or disabled ports may raise concerns about
specific protocols and IP addresses.

By utilizing these descriptors, a firewall can decide whether to quietly
ignore or transmit a response with an error to a data packet\'s
connection attempt.

**2.2. Firewall Types**

Different types of firewalls include various filtering methods. While
each type was developed to bypass previous generations of firewalls, the
underlying technology is largely shared between generations.

Firewall types are differentiated according to the following approaches:

Link Tracking

Filtering Rules

Audit Logs

![](media/image3.jpeg){width="5.177083333333333in"
height="3.5208333333333335in"}Each type operates at a different level of
the Open Systems Interconnection model (OSI), the standardized
communication model. This model provides a better visual of how each
firewall interacts with connections.

**Static Packet Filtering Firewall**

Also known as stateless control firewalls, operates at the OSI network
layer (layer-3). These firewalls provide basic filtering by checking all
individual data packets transmitted over the network; This check is
based on the source and destination information of the packets. In
particular, they do not keep track of previously confirmed connections,
so every data packet and connection must be reconfirmed.

The filtering process is based on IP addresses, ports and packet
protocols. This type of firewall prevents at least two networks from
connecting directly without permission. Filtering rules are based on a
manually created access control list. These rules are quite strict, and
properly shutting down unwanted traffic without compromising network
availability is a challenging process. Static filtering requires
constant manual revision to be used effectively. While this may be
manageable on small networks, it can quickly become challenging on
larger networks.

The inability to read application protocols means that the content of a
message delivered in a packet cannot be understood. Packet-filtering
firewalls that do not have the ability to read content have a limited
level of protection.

**Circuit Level Gateway Firewall**

Circuit-level gateways operate at the session level (layer 5). These
firewalls check for packets that are functional on a connection and - if
working well - allow a persistent open connection between the two
networks. Once the connection is successfully established, the firewall
stops checking the connection. Besides the connection approach, the
circuit-level gateway may have similar characteristics to proxy
firewalls. Ongoing unmonitored connections are risky; because legitimate
tools can open the connection and then allow a malicious actor to
constantly get in.

**Stateful Inspection Firewall**

Also known as dynamic packet filtering firewalls, stateful inspection
firewalls possess a distinctive capability in monitoring ongoing
connections and recalling past connections compared to static filtering.
Originally operating at the transport layer (Layer 4), these firewalls
have evolved to monitor multiple layers, including the application layer
(Layer 7) in contemporary settings.

Similar to static filtering firewalls, stateful inspection firewalls can
allow or block traffic based on technical specifications such as
specific packet protocols, IP addresses, or ports. However, these
firewalls additionally track and filter connection states uniquely using
a state table.

This firewall updates filtering rules based on historical connection
events logged in the state table by the routing device. While filtering
decisions typically rely on rules set by administrators when configuring
computer and firewall settings, the state table enables these dynamic
firewalls to make their own decisions based on past interactions they
have \"learned.\" For instance, traffic types that have caused issues in
the past may be filtered in the future. The flexibility of stateful
inspection has solidified its position as one of the most common types
of security shields available today.

**Proxy Security Firewall**

Proxy security firewalls, also known as application-level firewalls
(Layer 7), are unique in their ability to read and filter application
protocols. They combine application-level inspection or \'deep packet
inspection (DPI)\' with stateful inspection.

Proxy security firewalls provide protection closest to a real physical
barrier. Unlike other firewalls, they serve the dual role of being a
representative (or \'proxy\') for each network between external networks
and internal hosts.

Filtering is based on application-level data rather than just IP
addresses, ports, and basic packet protocols (UDP, ICMP) as in
packet-based security firewalls. Reading and understanding protocols
such as FTP, HTTP, DNS, and others allow for more in-depth examination
and cross-filtering of various data attributes.

Similar to a gatekeeper examining and assessing incoming data, it looks
for potential issues. If no problems are detected, the data is allowed
to pass through to the user.

The downside of such a robust security measure is that it can sometimes
block non-threatening data from coming through, leading to functional
delays.

**Next-Generation Firewall (NGFW)**

Continuously evolving threats demand more sophisticated solutions, and
next-generation firewalls effectively address this challenge by
combining the features of a traditional firewall with intrusion
prevention systems.

Designed to scrutinize and detect specific threats such as advanced
malware in more detail, these threat-specific next-generation firewalls
offer a comprehensive solution to filter risks. Widely adopted by
businesses and complex networks, these firewalls provide a holistic
approach to filtering threats.

**Hybrid Security Firewall**

Hybrid security firewalls utilize multiple firewall types within a
singular private network.

**III. IDS/IPS (Intrusion Detection and Prevention Systems)**

Intrusion Detection System (IDS) and Intrusion Prevention System (IPS)
devices are crucial network devices used to detect malicious activities
by examining network traffic. These systems are employed to safeguard
network infrastructures that hold critical importance for security.

IDS and IPS devices are configured to analyze network traffic in detail.
This configuration involves comparing data signatures to detect
predefined attacks. When attacks are identified, these systems can take
measures such as alerting the system administrator or blocking the
traffic involved in the attack. However, administrators often prefer to
receive alerts instead of blocking traffic, as even normal network
traffic can be perceived as an attack.

Alarms generated by IDS and IPS devices are typically categorized into
four groups: True-Positive, False-Positive, True-Negative, and
False-Negative. These categories represent malicious (True) or harmless
(False) situations, along with triggered (Positive) or non-triggered
(Negative) alarms.

Intrusion Prevention System (IPS) **attempts to detect attacks by
directly processing network traffic**. It compares incoming data with
malicious records stored in the database based on signatures and detects
attacks. However, due to the modifiability of signatures, it may not
provide complete protection. IPS has the capability to cut off data flow
directly upon detecting an attack but is often configured to generate
alerts.

On the other hand, an Intrusion Detection System (IDS) **does not pass
network traffic directly**. Instead, it receives a copy of data flow
through a switch. It analyzes the copied data to detect attacks. IDS
does not have the ability to prevent attacks but logs send alerts and
informs the system administrator about potential attacks. IDS typically
analyzes and reports on the dynamics of the network.

IDS and IPS are crucial security devices used to protect network
infrastructures critical for security and detecting attacks. These systems
play a critical role in defending computer networks against external
attacks and minimizing potential security breaches.

![](media/image4.png){width="6.3in" height="3.7319444444444443in"}

**IV. ANTIVIRUS SOFTWARE**

Antivirus software is security programs developed to protect computer
systems from malicious software, such as viruses, worms and trojans.
This software is designed to detect, block, examine and remove viruses
and other types of malware from computers, networks and other devices.
Often offered as part of a security suite, antivirus software is also
available as a standalone option.

Antivirus programs are often installed to proactively protect computers
against cyber threats. These software can help protect against a variety
of cyber threats, such as keyloggers, browser hijackers, trojans, worms,
rootkits, spyware, adware, botnets, phishing attempts, and ransomware
attacks.

Malware samples often represent a type that antivirus software tries to
block. Antivirus programs act as a background process to limit and
prevent the spread of malware by scanning computers, servers or mobile
devices. Most antivirus software includes real-time threat detection and
protection features; thus protecting against potential security
vulnerabilities and scanning system files regularly.

**Antivirus software generally performs the following essential
functions in network security:**

-   Scanning directories or specific files using a library of known
    malicious signatures to detect signs of malware.

-   Providing users with the option to schedule automatic scans.

-   Allowing users to initiate new scans at any time.

-   Automatically removing detected malware in the background or
    alerting users about infections and prompting them to clean the
    files.

**The advantages of antivirus software are as follows:**

-   Virus and Malware Protection: Primarily designed to protect against
    malicious viruses, malware, and spyware.

-   Spam and Pop-up Protection: Automatically blocks infiltration
    attempts through pop-up ads and malicious web pages, enhancing
    system security.

-   Web Protection: Guards users against phishing attempts and
    fraudulent websites aiming to collect credit card and bank
    information.

-   Real-Time Protection: Scans every incoming file and program in
    real-time, automatically intervening and preventing the spread when
    a threat is detected.

**However, there are some challenges associated with antivirus
software:**

-   Antivirus programs using only signature-based detection cannot
    identify new malware types and variations of existing ones.

-   Even the best antivirus software may mistakenly identify a safe
    program or file as malicious, leading to its quarantine.

-   Antivirus software can hinder system updates or cause interruptions
    in the middle of these updates.

-   Antivirus software often consumes excessive system resources,
    leading to performance issues and noticeable delays in the network.

-   For comprehensive protection, it is usually recommended to use
    antivirus options alongside hardware and software-based security
    firewalls.

-   Evolving technology trends such as the metaverse, Web3, fintech, and
    autonomous vehicles can make finding the right antivirus protection
    more challenging. Traditional antivirus technologies may not detect
    modern fileless attacks are carried out using trusted systems like
    PowerShell.

**Other features include:**

-   Boot-scan Command: Prevents viruses from replicating themselves with
    a boot-scan command triggered by antivirus software while the system
    is shut down.

-   Dark Web Scan: Checks whether users\' sensitive information has been
    leaked on the dark web, where most data breaches, such as ransom
    attacks, typically occur.

-   Protection from External Devices: Prevents the entry of malicious
    viruses into systems by regularly scanning external devices, such as
    hard drives and USB adapters.

-   Antivirus software is available in various forms, including
    standalone antivirus scanners, machine learning and cloud-based
    programs, and internet security software packages offering malware
    signatures and antivirus protection. Popular manufacturers such as
    AVG Technologies, Kaspersky, Malwarebytes, McAfee, Norton, and Trend
    Micro provides both free and commercial antivirus products.

**Protection Against Malicious Software**

Antivirus software is designed to protect computer systems from
malicious software such as viruses, worms, trojans, etc. For example,
when a user opens an email attachment, antivirus software scans this
attachment to prevent potential threats.

**Real-Time Scanning**

Antivirus software scans files in real-time during instant actions like
downloading files or opening email attachments. If a threat is detected
when a user opens a file, immediate intervention prevents the spread of
malware.

**4.1. Security Updates**

Antivirus software consistently updates virus databases. These updates
provide protection against newly emerging viruses and enhance the
effectiveness of the software.

Considering the differences between corporate needs and home users,
traditional desktop-based protection measures alone are no longer
sufficient in today\'s environment. Therefore, the scanning of viruses
by a central structure before entering the local network has become
crucial.

Given that email, HTTP, and FTP traffic are the most common services
through which viruses spread, antivirus logic is directed to the
antivirus gateway using firewall principles. Antivirus systems installed
on mail servers neutralize viruses circulating through email within the
local network. Additionally, virus protection software installed on
server computers and software that monitors employees\' systems provide
a corporate antivirus solution. These systems can be centrally
controlled from a single point, allowing for the reception and
distribution of antivirus update files. Features such as centralized
reporting and automatic updates make tasks more manageable.

**4.2. Antivirus Protection Selection Criteria:**

-   Performance Impact: The use of antivirus software should not result
    in any performance loss.

-   International Certifications: It is important for antivirus software
    to have internationally recognized certifications.

-   Scanning Capabilities: The software should be capable of effectively
    scanning for all types of malicious code, including trojans,
    droppers, ActiveX, and Java.

-   Security Updates: The antivirus software should be integrated into
    the system and provide regular updates to ensure security.

-   Centralized Management: The ability to manage the entire virus
    protection system from a single point is advantageous.

-   Reporting and Automatic Updates: Features such as centralized
    reporting and automatic updates make processes easier by optimizing
    security procedures.

**V. CRYPTOGRAPHY AND ENCRYPTION TOOLS**

Cryptography involves the creation of algorithms that encrypt the data
to be protected and can reverse this encrypted data to its original
form. The encrypted data typically appears as a random sequence of
characters. The keys used for encryption and decryption are often
associated with each other and should be derivable from one another.
Cryptography establishes protocols to ensure the security of private
communication and includes the analysis of these protocols.

![](media/image5.png){width="6.3in" height="3.15in"}In today\'s
digitized world, security measures such as two-factor authentication on
social media platforms and end-to-end encryption have become integral
parts of cryptography. The encryption of private communication and the
deciphering of these codes have become more intricate with the
advancement of computers and the internet.

**5.1. The Role of Cryptography in Cybersecurity**

Cryptography aims to create robust encryption systems for use in
cybersecurity. As complete protection is impossible due to user
negligence when combined with computer programs, encryption systems are
still utilized to secure sensitive information. In the realm of
cybersecurity, cryptography plays a vital role in safeguarding network
communications. It provides a crucial layer of defense against
unauthorized access, ensuring that sensitive data remains confidential
and integral. Cryptographic techniques, such as secure key exchange and
encryption algorithms, contribute significantly to fortifying network
security, making it more challenging for malicious actors to compromise
the integrity and confidentiality of data during transmission over
networks.

**5.2. The Strength of a Cipher in Cryptography**

For a cipher to be suitable for cryptography, it depends on four
fundamental parameters:

1\. Confidentiality: This involves ensuring that data can only be accessed by
designated parties; otherwise, communication is not secure.

2\. Authenticity/Integrity: Ensures that the received data is not
altered, and it is crucial that the data is received as sent by the
sender.

3\. Non-Repudiation: Addresses the situation where the sender cannot
deny the information they sent.

4\. Authentication: Both the sender and receiver must authenticate each
other\'s identities and verify the source of the data.

**5.3. Exemplary Cryptographic Applications**

SSL/TLS Protocols: Employed for encrypting data communication over the
internet, commonly used in banking transactions and e-commerce websites.

PGP (Pretty Good Privacy): Utilized to encrypt personal and professional
communications particularly preferred for email security.

IPSec (Internet Protocol Security): Used to ensure secure communication
through virtual private networks.

**5.4. Cryptographic Techniques**

Cryptography, a discipline that involves a set of techniques and
mathematical methods to securely transmit or store information, utilizes
various fundamental techniques. Here is a detailed explanation of the
key techniques in cryptography:

1\. Symmetric-Key Encryption:

-   In this technique, the same key is used for both encryption and
    decryption processes.

-   Secure transmission of the key between the parties is crucial.

-   Effective for ensuring data confidentiality, but key management can
    be challenging.

2\. Public-Key Encryption:

-   Different keys are used for encryption and decryption, with one key
    encrypting the data and the other decrypting it.

-   Each user is provided with a key pair: a public key (open to
    everyone) and a private key (known only to the owner).

-   Key management is more straightforward, but it may be slower than
    symmetric-key encryption.

3\. Hash Functions:

-   Takes an input and produces a fixed-length unique output.

-   Commonly used to verify data integrity.

-   Always produces the same output for the same input, but the reverse
    is practically impossible.

-   Cryptographic hash functions must be resistant to specific types of
    attacks.

Cryptography also includes the following elements:

\- Digital Signatures: Used to authenticate the sender of data. Data
signed with a private key can be verified with the public key.

\- Key Exchange Protocols: Used between parties wishing to securely
exchange keys. For instance, the Diffie-Hellman key exchange protocol.

\- Timestamps: Used to verify when data was created.

\- Random Number Generators: Used to generate random numbers for
security protocols.

A combination of these techniques is employed in modern cryptographic
systems to ensure security. Cryptography plays a fundamental role in
information security and evolves continuously to remain resilient
against emerging threats as technology advances.

**VI. OTHER NETWORK SECURITY APPLICATIONS AND TOOLS**

**6.1. Network Access Control (NAC)**

Network Access Control (NAC) serves as a foundational element in network
security, presenting one of the simplest yet most effective methods. Its
primary objective is to ensure the absence of unauthorized clients or
users in the network. NAC utilizes the 802.1x protocol, employing the
MAC addresses of user computers seeking network access. Operating
through the Identity and Access Management (IAM) component, NAC manages
authorization and permission controls. IAM, alongside predefined rules,
guides NAC in accepting or rejecting access requests. NAC, during
initial implementation, identifies devices with instant network access,
defines their types, and ensures actions align with specified policies.
NAC systems often offer fine-tuning settings for determining rules and
permissions from an extensive product list.

Two implementation approaches of NAC include pre-admission and
post-admission. Pre-admission decides whether a user gains permission to
join the network, rejecting users before they gain access.
Post-admission allows users, after joining the network, to access
permitted applications within the scope of their assigned rights.

![](media/image6.jpeg){width="5.366666666666666in"
height="3.111111111111111in"}

**Key features and benefits of NAC encompass:**

Enforcing defined rules across all systems without requiring a separate
device or module.

Safeguarding against Zero-Day attacks.

Enabling user and device identification, profile creation, and
authorization.

Managing guest user network access and offering services like guest
management portals.

Ensuring compliance with security policies and preventing access by
non-compliant devices.

Providing role-based control over users, devices, and applications.

Integrating with other security and network solutions.

As components necessitating control, such as securing data across
various locations, BYOD, IoT devices, guest user control, and rogue
endpoints, continue to grow, NAC becomes more prevalent. Additionally,
its ability to provide access control for both wired and wireless
networks is a significant advantage.

**The Significance of NAC (Network Access Control)**

NAC is a security solution that enhances visibility in corporate networks by
classifying devices accessing the network at endpoints based on specific
policies, reducing risks. Access control offers management over the
operations an individual can perform on the network they are accessing.

The NAC system progresses through four stages: authentication,
authorization, security scanning, and improvement. These stages involve
verifying the identity of corporate staff for network access control,
authorizing access, conducting security scans, and continually enhancing
security measures.

The NAC solution aims to automatically identify devices connecting to
the network, prevent insecure access and mitigate security
vulnerabilities. Particularly with the increasing security risks
associated with BYOD, IoT devices, and guest user control, the
importance of NAC continues to grow.

**6.2. Web Application Security**

Conducting security tests on web applications that handle sensitive user
information, such as in banking and e-commerce, is crucial for
safeguarding companies\' internal and external resources.
Vulnerabilities and loopholes in internet applications can provide
attackers with an opportunity to infiltrate internal networks. The
complex structure of web server applications, the potential
vulnerability of database applications to code injection attacks, and
the presence of insecurely written code, not considering security, can
expose organizations to various types of attacks. Particularly,
applications that take user input, execute code in the background and
interact with databases facilitate web attacks. The diversity in
configurations and services, along with the variety of user permissions,
enriches the attack vector of web applications. Components in the
application layer and HTTP protocol are more influential in the
emergence of web security vulnerabilities than those at the network
layer.

![](media/image7.png){width="5.816666666666666in"
height="4.361805555555556in"}

**Critical components that need to be considered for the secure design
of web applications:**

1\. Control of User Inputs:

Input fields from users require thorough security checks due to the risk
of malicious users exploiting vulnerabilities by injecting harmful code
or commands instead of normal data. HTML and JavaScript language rules
often do not provide sufficient security control. Therefore, it is
crucial to validate the legitimacy of user input before it is used on
the server side. White-listing and black-listing methods can be used for
input control. White-listing restricts inputs to specific data types
while black-listing filters potential malicious requests.

2\. Secure Session Management:

User sessions represent access to sensitive information in web
applications. Unauthorized access to this information could lead to the
imitation of a user\'s identity by a malicious actor. Secure session
management involves measures such as encrypting session data,
determining session timeouts, ensuring the security of session
authentication processes, and securely storing session keys.

3\. Firewalls and Security Policies:

Firewalls should be employed to enhance the security of web
applications. Firewalls monitor network traffic and prevent malicious
requests. Security policies encompass the rules and standards set by an
organization for its web applications. These policies increase the
security awareness of the development team, ensuring adherence to
security standards during the application development process.

4\. Use of SSL/TLS:

Using SSL/TLS protocols during data transmission enhances the security
of web applications. These protocols ensure that data is securely
transmitted when users communicate with a website, contributing to the
protection of sensitive information.

5\. Monitoring and Updating Software Dependencies:

Web applications utilize various components and libraries, which may
contain security vulnerabilities. Therefore, regular updates and
monitoring of the security vulnerabilities of the used software and
dependencies are essential. Continuous efforts to identify and address
security vulnerabilities are crucial to making web applications more
secure. A development team with security training is a critical part of
the secure software development process.

**6.3. Mobile Device Management (MDM)**

![](media/image8.jpeg){width="5.415277777777778in"
height="2.7069444444444444in"}Mobile Device Management (MDM) plays a
pivotal role in organizations extensively utilizing mobile devices such
as smartphones, tablets, and laptops.

The importance of MDM can be highlighted in several key aspects:

**Data Security:**

Enterprise mobile devices frequently handle critical business data,
making their security paramount. In the event of device loss, theft, or
hacking, a significant security threat arises. MDM addresses this by
empowering IT and Security teams to implement policies, encryption, and
remote management features. In cases of lost devices, administrators can
remotely wipe sensitive data, preventing unauthorized access.

**Device Management:**

MDM facilitates centralized management of all company devices,
regardless of type or operating system. It simplifies the provisioning,
configuration, and management processes, ensuring compliance with
security policies.

**Security Policies:**

MDM aids in enforcing security policies on mobile devices.
Administrators can define policies related to passcode protection,
camera usage, Wi-Fi connectivity, and other customization options. This
ensures that devices accessing corporate data adhere to specific
security standards.

**Application Security:**

MDM solutions extend beyond device management to secure the applications
installed on these devices. Application security features may include
app wrapping, where security features are applied to an application
before redeployment.

**Identity and Access Management (IAM):**

Strong IAM is crucial for secure mobile management. MDM enables
organizations to manage user identities associated with devices,
regulating access through features like single sign-on (SSO) and
multifactor authentication.

**Endpoint Security:**

MDM addresses endpoint security concerns, encompassing all devices
accessing the corporate network, including wearables and IoT devices. It
incorporates standard security tools like antivirus software, network
access control, incident response, and cloud security.

**BYOD (Bring Your Own Device):**

MDM is particularly critical in the context of BYOD, where employees use
personal devices for work. It ensures that even personal devices adhere
to security standards and do not compromise enterprise data.

**Enterprise Mobility Management (EMM) and Unified Endpoint Management
(UEM):**

MDM is a component of broader solutions like EMM and UEM, which cover
application and endpoint management, BYOD, providing a holistic approach
to security.

**Remote Monitoring and Control:**

MDM enables real-time monitoring, updating, and troubleshooting of
devices. It allows IT professionals to remotely lock or wipe a device in
case of loss or theft.

**Compliance and Reporting:**

MDM solutions often include reporting tools and assisting organizations in
assessing device compliance with security policies. This provides
insights into potential risks and areas of improvement.

In summary, MDM is instrumental in maintaining a secure and well-managed
mobile device environment within an organization, ensuring the
confidentiality and integrity of sensitive data.

**5.4. Virtual Private Networks (VPN)**

A Virtual Private Network (VPN) is a network security tool designed to
safeguard users\' internet connections and online privacy. It
establishes an encrypted connection over the internet, creating a secure
tunnel between a device and the network. By masking the user\'s IP
address, VPNs ensure online activities remain private and untraceable.

The encrypted connection forms a tunnel between a local network and an
exit node in another location, ensuring message encryption throughout
its entire journey. This encryption prevents access by internet service
providers or any third parties, making intercepted data appear as
unintelligible.

**VPNs serve to hide various aspects, including:**

1\. Devices: Protecting laptops, tablets, and mobile phones from
cybercriminals, especially when connected to public Wi-Fi, preventing
Man-in-the-Middle attacks.

2\. IP Address and Location: Masking the actual IP address to appear as
if connecting from a different location, the physical location of the
VPN server.

3\. Browsing History: Ensuring a private and secure browsing experience
by hiding IP addresses, preventing ISPs and web browsers from monitoring
online activities.

**Business Benefits of VPN:**

1\. Secured Connection to Shared Resources: VPNs, particularly those
utilizing IP whitelisting, protecting connections to cloud storage,
file-sharing services, and work applications containing sensitive
corporate data.

2\. Cost Saving without Jeopardizing Security: Eliminating the need for
expensive physical network connections, VPNs save costs and resources
while avoiding extra IT administration workload.

3\. Securing Data on Mobile Devices: Installing VPN clients on
smartphones protect remote workers from accessing company servers via public
Wi-Fi, safeguarding against potential data breaches.

![](media/image9.jpeg){width="4.311111111111111in"
height="4.266666666666667in"}In conclusion, advancements in VPN
technology has addressed historical issues such as slow speeds, making
VPNs are an essential investment for businesses aiming to secure their data
without compromising on performance. While cost-effective VPN services
are available, the potential cost of failed security outweighs the
investment in reliable VPN solutions.

**VII. CONCLUSION**

Nowadays, network security applications and tools play a vital role in
providing protection against various threats existing in the digital
world. Firewalls, IDS/IPS, antivirus software, cryptography, and other
network security tools collaborate as a whole to ensure information
security. These tools play an important role in providing effective
protection in an environment where digital threats are constantly
evolving.

Creating an up-to-date and effective network security strategy against
ever-increasing digital threats is vital for individuals and
organizations. Taking a proactive approach not only against current
threats, but also against unknown threats that may arise in the future,
is critical to strengthening information security.

Therefore, constantly reviewing, updating and improving network security
strategies; It is important to adapt to new security threats. In this
context, the interoperability of network security applications and tools
is of critical importance for integrity and effectiveness. In this way,
a stronger and more durable information security infrastructure can be
created against the rapidly changing dynamics of the digital world.

**VIII. REFERENCES:**

\"Network Security Tools and Applications in Research Perspective.\"
Proceedings of the Third International Conference on I-SMAC (IoT in
Social, Mobile, Analytics and Cloud) (I-SMAC 2019), IEEE Xplore, ISBN:
978-1-7281-4365-1, Part Number: CFP19OSV-ART.

Kaya, O. F., & Öztürk, E. (2017). Veri ve Ağ Güvenliği İçin Uygulama ve
Analiz Çalışmaları. İstanbul Ticaret Üniversitesi Fen Bilimleri Dergisi,
16(31), 85-102.

Baykara, M., Daş, R., & Karadoğan, İ. (2013). Bilgi Güvenliği
Sistemlerinde Kullanılan Araçların İncelenmesi. 1st International
Symposium on Digital Forensics and Security (ISDFS'13), 20-21 Mayıs
2013, Elazığ, Türkiye.

<https://sibermetin.com>

[https://www.kaspersky.com](https://www.kaspersky.com.tritions/)

<https://www.redbilisim.com/internet-ve-ag-guvenligi>

[https://hukukvebilisim.org](https://hukukvebilisim.org-)

[https://elfanet.com.tr](https://elfanet.com.tr/tr/main/article/nac-network-access-control-nedir-neden-onemli/77#:~:text=NAC%20Nedir%3F,kontroll%C3%BC%20sa%C4%9Fland%C4%B1%C4%9F%C4%B1%20bir%20g%C3%BCvenlik%20%C3%A7%C3%B6z%C3%BCm%C3%BCd%C3%BCr)

[https://www.ibm.com](https://www.ibm.com/topics/mobile-device-management)
