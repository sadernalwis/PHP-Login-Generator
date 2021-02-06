## PHP Login Generator for Linux
### NginX | MySQL | PHP | Bootstrap UI | SwiftMailer
[![License: MIT](https://img.shields.io/badge/License-MIT-orange.svg)](https://opensource.org/licenses/MIT)

<br></br>
### Base Template Structure
```
/var/www/domain-name-test.org/
├── config
│   └── db.php
├── controllers
│   ├── index.php
│   ├── login.php
│   ├── register.php
│   └── user_activation.php
├── css
│   └── style.css
├── dashboard.php
├── index.php
├── logout.php
├── signup.php
└── user_verification.php
```

#### To build & configure a PHP site Login system run the following commands and follow instructions.
```
cd ~
git clone https://github.com/sadernalwis/PHP-Login-Generator.git
cd PHP-Login-Generator

./BUILD.sh
```
#### test with the browser:
```
http://yourIP_or_domain/index.php
```
#### test via CLI:
```
curl -I http://yourIP_or_domain/index.php
```

<img align="center" src="docs/screenshot.png" width="600px"/>

#### TODO
* SSL
* Multiple Templates
* MIME type configurations

 