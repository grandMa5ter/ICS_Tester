# ICS_Tester
This repository is dedicated to a script that evaluates some of IEC62443-3-3 system level control sets as well as IEC62443-4-2 component level control sets. This tool aspire to be a measuring stick for a component or system to check itself against the control set of the standard and a look to see what security level it can achieve on the scale of IEC62443 SL0-4 in FR 1-7.

# Origin
ICS_Tester was inspired by a project that I was managing few months back and I never got to completely finish it and implement the code and test systems. Good! Now I can develop the code in my own time and provide it to community free of charge for others. If you require to carry out a Factory Acceptance Test (FAT) or Site Acceptance Test (SAT) on a piece of equipment on-site or in-lab, you can use this script to check the device against the standard. 
If you see that your platform is not covered by the code/script, please contribute to the code and let's make it universal or alternatively if you have an indepth manual of the component/system, please share it with me so that I know which options needs to be checked.

# Target Systems
For now, I'm begining to write the Powershell script to check few things off the list of controls that are supposed to be implemented by the stanards. 

# Limitations
For now from the outset, I know all codes must be able to run natively, so each platform code must be written in a way that can be executed solely on that platform without dependancy. Therefore, I can't write the whole code in python or any other language as it should be able to execute natively within industrial control environment.

I will write about limitation and this section will grow as some controls cannot be tested by script and must be manually checked.


#Future / TODO
- RHEL Compatible Implementation
- Ubuntu Compatible Implementation
- Windows 7 Compatible Implementation
- Windows Server 2012, 2017, 2019 Compatible Implementation
- Importing of XML file (settings) for checking
- Export Report of Markdown, CSV, XML for better viewing
- Custome import, export

# Contributions
I have created multiple things during my career in field of Cyber Security within Industrial Control or OT. However, they were always hidden and protected by IP of organisations. This time, I want to create something that it is not public or publicly available and everyone can use it in their work and can contribute to it to make it better.
I cannot share the full text of IEC62443-3-3 and 4-2 control set publicly as it is protected by IP. However, the purpose of contribution might be better to be at code level for optimised checking, fancy reporting and/or contribution of checking for other platforms (IoT), OSes (*nix), PLC, IED etc etc...

# Disclaimer: 
While ICS_Tester endeavors to perform as much identification and enumeration of control implementation, there is no guarantee that every control will be identified and checked, or that every platform will be fully enumerated for control checks. Users of ICS_Test (especially practitionars and Cyber Security Experts) should perform their own manual checks and balances. **Do not rely on this tool alone for your FAT/SAT tests and or certification for ISA Standard Compliance**.
