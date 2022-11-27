# SynDetectionSystem

A common problem that webservers face is denial of service attack. In this repo we target specific type of attack “Syn Flooding” on TCP port of the server. The detection of this type of attack is being done by training a Long short-term memory model (LSTM). A dataset was created using python script with Pyshark library to sniff packets oncoming on the webserver. This dataset was then passed through the model. The model can accurately predict the trend of normal network traffic and syn packets designed to choke the network [1]. The model accuracy was 99% and when tested on simulated environment showed that the model was performing accurately to detect normal flow of traffic and syn packets.

[1] Li, Yijie, Boyi Liu, Shang Zhai, and Mingrui Chen. "DDoS attack detection method based on feature extraction of deep belief network." In IOP Conference Series: Earth and Environmental Science, vol. 252, no. 3, p. 032013. IOP Publishing, 2019. 


- Just need to run packet_captor.py to detect packets.
- If a syn attack is being carried out the script will detect it.
- I have also attached django webserver named as ecommerce site. (not my own)
- You can use Hulk to send SYN packets.
- Browse normally on django webserver the model is trained based on that.
- The model was not working properly and my teammate and friend fixed it for me to credit for Bidirectional LSTM goes to Uzair Mughal

Contributor: https://github.com/uzairmughal20

Feel free to contact me if there is any problem.
