#!/bin/bash
HISTFILE=~/.bash_history
set -o history
PHP_ROOT=(~/RubyOS/web/cloudcone/)
DOMAIN=domain-name-test.org
MYSQL_USERNAME=newuser
MYSQL_PASSWORD=Password123@
MYSQL_SCRIPTS_PATH=$(pwd)/mysql
# PHP_SCRIPTS_PATH=$(pwd)/php
PHP_SCRIPTS_PATH=/var/www/$DOMAIN
# IP_ADDRESS=$(ip addr show eth0 | grep inet | awk '{ print $2; }' | sed 's/\/.*$//')
# IP_ADDRESS=$(ip addr show wlp8s0 | grep inet | awk '{ print $2; }' | sed 's/\/.*$//')
IP_ADDRESS=192.168.8.106
# curl -4 icanhazip.com
screen () {
    trap "tput rmcup; exit"  SIGHUP SIGINT SIGTERM ## Restores the screen when the program exits.
    tput smcup ## Saves the screen contents.
    clear ## Clears the screen.
    tree $PHP_SCRIPTS_PATH
    echo "Enter \`y\` to confirm."$'\n'
}
cd $PHP_ROOT
sudo mkdir -pv $USER /var/www/$DOMAIN/
sudo chown -Rv $USER /var/www/$DOMAIN/
read -p "check $PHP_SCRIPTS_PATH ownership!"$'\n' confirmation   </dev/tty
COMMANDS=(
    "refer"
    "update"
    "Nginx"
    "MySQL"
    "PHP"
    "database"
    "config/db.php"
    "index.php"
    "css/style.css"
    "composer"
    "swiftmailer"
    "controllers/register.php"
    "signup.php"
    "controllers/user_activation.php"
    "user_verification.php"
    "controllers/login.php"
    "controllers/index.php"
    "dashboard.php"
    "logout.php")
COUNTER=0
for command in "${COMMANDS[@]}"; do
    screen
    COUNTER=$[$COUNTER+ 1]
    printf "$COUNTER/${#COMMANDS[@]}:\t"
    if [[ $command == "refer" ]] ;then
        read -p "see references?"$'\n' confirmation   </dev/tty
        if [[ "$confirmation" == "y" ]]; then
            printf "https://www.digitalocean.com/community/tutorials/how-to-install-linux-nginx-mysql-php-lemp-stack-ubuntu-18-04"$'\n'
            printf "https://www.digitalocean.com/community/tutorials/how-to-install-linux-nginx-mysql-php-lemp-stack-on-ubuntu-20-04"$'\n'
            printf "https://www.positronx.io/build-php-mysql-login-and-user-authentication-system/"$'\n'
            read -p ""$'\n' confirmation   </dev/tty
        fi
    elif [[ $command == "update" ]];then
        read -p "$command?"$'\n' confirmation   </dev/tty
        if [[ "$confirmation" == "y" ]]; then
            sudo apt update
        fi
    elif [[ $command == "Nginx" ]];then
        read -p "install $command?"$'\n' confirmation   </dev/tty
        if [[ "$confirmation" == "y" ]]; then
            sudo apt install nginx
            sudo ufw app list
            sudo ufw allow 'Nginx HTTP'
            printf "try http://${IP_ADDRESS}"$'\n'
            printf "or curl -4 icanhazip.com"$'\n'
            read -p ""$'\n' confirmation   </dev/tty
        fi
    elif [[ $command == "MySQL" ]];then
        read -p "install $command?"$'\n' confirmation   </dev/tty
        if [[ "$confirmation" == "y" ]]; then
            sudo apt install mysql-server
            printf "entering mysql_secure_installation"$'\n'
            sudo mysql_secure_installation
            read -p "enter MySQL setup?"$'\n' confirmation   </dev/tty
            sudo mysql
        fi
    elif [[ $command == "PHP" ]];then
        read -p "install $command?"$'\n' confirmation   </dev/tty
        if [[ "$confirmation" == "y" ]]; then
            sudo apt install php-fpm php-mysql
            sudo mkdir /var/www/$DOMAIN
            sudo chown -R $USER:$USER /var/www/$DOMAIN
            sudo chown -R $USER:$USER /etc/nginx/sites-available/
cat > /etc/nginx/sites-available/$DOMAIN <<-EOF
server {
    listen 80;
    server_name ${IP_ADDRESS} ${DOMAIN} www.${DOMAIN};
    root /var/www/${DOMAIN};
    index index.html index.htm index.php;
    
    location / {
      try_files $uri $uri/ @backend;
    }

    location /css/ {
    }


    location @backend {
      proxy_pass http://${IP_ADDRESS};
    }
    location ~ \.php$ {
        include snippets/fastcgi-php.conf;
        fastcgi_pass unix:/var/run/php/php8.0-fpm.sock;
    }
    location ~ /\.ht {
        deny all;
    }
}
EOF
            sudo ln -s /etc/nginx/sites-available/$DOMAIN /etc/nginx/sites-enabled/
            sudo nginx -t
            sudo systemctl reload nginx
cat > /var/www/$DOMAIN/index.html <<-EOF
<html>
    <head>
        <title>${DOMAIN} website</title></head>
    <body>
        <h1>Hello World!</h1>
        <p>This is the landing page of <strong>${DOMAIN}</strong>.</p></body>
</html>
EOF
            printf "try http://${DOMAIN}"$'\n'
cat > /var/www/$DOMAIN/info.php <<-EOF
<?php
    // Show all information, defaults to INFO_ALL
    phpinfo();
    // Show just the module information. identical phpinfo(8)
    phpinfo(INFO_MODULES);
?>
EOF
            printf "try http://${DOMAIN}/info.php"$'\n'
        fi
    elif [[ $command == "database" ]];then
        read -p "initialize users?"$'\n' confirmation   </dev/tty
        if [[ "$confirmation" == "y" ]]; then
            # sudo mysql -u $MYSQL_USERNAME -p -t -vvv  < $MYSQL_SCRIPTS_PATH/init.sql > $MYSQL_SCRIPTS_PATH/init-output.txt
            sudo mysql -u $MYSQL_USERNAME -p -t -vvv  < $MYSQL_SCRIPTS_PATH/create-users.sql > $MYSQL_SCRIPTS_PATH/create-users.txt
        fi
    elif [[ $command == "config/db.php" ]];then
        read -p "setup $command?"$'\n?' confirmation   </dev/tty
        if [[ "$confirmation" == "y" ]]; then
            mkdir -vp $PHP_SCRIPTS_PATH/config
cat > $PHP_SCRIPTS_PATH/$command <<-EOF
<?php 
    // Enable us to use Headers
    ob_start();
    // Set sessions
    if(!isset(\$_SESSION)) {
        session_start();
    }
    \$hostname = "localhost";
    \$username = "${MYSQL_USERNAME}";
    \$password = "${MYSQL_PASSWORD}";
    \$dbname = "mysql";
    \$connection = mysqli_connect(\$hostname, \$username, \$password, \$dbname) or die("Database connection not established.")
?>
EOF
        fi
    elif [[ $command == "index.php" ]];then
        read -p "$command?"$'\n?' confirmation   </dev/tty
        if [[ "$confirmation" == "y" ]]; then     
cat > $PHP_SCRIPTS_PATH/$command <<-EOF
<!doctype html>
<html lang="en">
<head>
    <meta charset="utf-8">
    <meta name="viewport" content="width=device-width, initial-scale=1, shrink-to-fit=no">
    <link rel="stylesheet" href="https://stackpath.bootstrapcdn.com/bootstrap/4.5.0/css/bootstrap.min.css">
    <link rel="stylesheet" href="css/style.css">
    <title>PHP Login System</title>
    <!-- jQuery + Bootstrap JS -->
    <script src="https://ajax.googleapis.com/ajax/libs/jquery/3.5.1/jquery.min.js"></script>
    <script src="https://stackpath.bootstrapcdn.com/bootstrap/4.5.0/js/bootstrap.min.js"></script>
</head>
<body>
    <!-- Login form -->
    <div class="App">
        <div class="vertical-center">
            <div class="inner-block">
                <form action="" method="post">
                    <h3>Login</h3>
                    <div class="form-group">
                        <label>Email</label>
                        <input type="email" class="form-control" name="email_signin" id="email_signin" />
                    </div>
                    <div class="form-group">
                        <label>Password</label>
                        <input type="password" class="form-control" name="password_signin" id="password_signin" />
                    </div>
                    <button type="submit" name="login" id="sign_in"
                        class="btn btn-outline-primary btn-lg btn-block">Sign
                        in</button>
                </form>
            </div>
        </div>
    </div>
</body>
</html>
EOF
        fi
    elif [[ $command == "css/style.css" ]];then
        read -p "$command?"$'\n?' confirmation   </dev/tty
        if [[ "$confirmation" == "y" ]]; then
            mkdir -vp $PHP_SCRIPTS_PATH/css
cat > $PHP_SCRIPTS_PATH/$command <<-EOF
* {
  box-sizing: border-box;
}
body {
  font-weight: 400;
  background-color: #EEEFF4;}
body,
html,
.App,
.vertical-center {
  width: 100%;
  height: 100%;}
.navbar {
  background: #1833FF !important;
  width: 100%;}
.btn-outline-primary {
  border-color: #1833FF;
  color: #1833FF;}
.btn-outline-primary:hover {
  background-color: #1833FF;
  color: #ffffff;}
.vertical-center {
  display: flex;
  text-align: left;
  justify-content: center;
  flex-direction: column;}
.inner-block {
  width: 450px;
  margin: auto;
  background: #ffffff;
  box-shadow: 0px 14px 80px rgba(34, 35, 58, 0.2);
  padding: 40px 55px 45px 55px;
  transition: all .3s;
  border-radius: 20px;}
.vertical-center .form-control:focus {
  border-color: #2554FF;
  box-shadow: none;}
.vertical-center h3 {
  text-align: center;
  margin: 0;
  line-height: 1;
  padding-bottom: 20px;}
label {
  font-weight: 500;}
EOF
        fi
    elif [[ $command == "composer" ]];then
        read -p "install $command 2.0 for PHP?"$'\n?' confirmation   </dev/tty
        if [[ "$confirmation" == "y" ]]; then
            curl -sS https://getcomposer.org/installer -o composer-setup.php
            HASH=`curl -sS https://composer.github.io/installer.sig`
            php -r "if (hash_file('SHA384', 'composer-setup.php') === '$HASH') { echo 'Installer verified'; } else { echo 'Installer corrupt'; unlink('composer-setup.php'); } echo PHP_EOL;"
            sudo php composer-setup.php --install-dir=/usr/local/bin --filename=composer
            composer
        fi
    elif [[ $command == "swiftmailer" ]];then
        read -p "install $command plugin?"$'\n?' confirmation   </dev/tty
        if [[ "$confirmation" == "y" ]]; then
            composer require "swiftmailer/swiftmailer:^6.0"
        fi
    elif [[ $command == "controllers/register.php" ]];then
        read -p "$command?"$'\n?' confirmation   </dev/tty
        if [[ "$confirmation" == "y" ]]; then
            mkdir -vp $PHP_SCRIPTS_PATH/controllers
cat > $PHP_SCRIPTS_PATH/$command <<-EOF
<?php
    // Database connection
    include('config/db.php');
    // Swiftmailer lib
    require_once './lib/vendor/autoload.php';
    // Error & success messages
    global \$success_msg, \$email_exist, \$f_NameErr, \$l_NameErr, \$_emailErr, \$_mobileErr, \$_passwordErr;
    global \$fNameEmptyErr, \$lNameEmptyErr, \$emailEmptyErr, \$mobileEmptyErr, \$passwordEmptyErr, \$email_verify_err, \$email_verify_success;
    // Set empty form vars for validation mapping
    \$_first_name = \$_last_name = \$_email = \$_mobile_number = \$_password = "";
    if(isset(\$_POST["submit"])) {
        \$firstname     = \$_POST["firstname"];
        \$lastname      = \$_POST["lastname"];
        \$email         = \$_POST["email"];
        \$mobilenumber  = \$_POST["mobilenumber"];
        \$password      = \$_POST["password"];
        // check if email already exist
        \$email_check_query = mysqli_query(\$connection, "SELECT * FROM users WHERE email = '{\$email}' ");
        \$rowCount = mysqli_num_rows(\$email_check_query);
        // PHP validation
        // Verify if form values are not empty
        if(!empty(\$firstname) && !empty(\$lastname) && !empty(\$email) && !empty(\$mobilenumber) && !empty(\$password)){
            // check if user email already exist
            if(\$rowCount > 0) {
                \$email_exist = '
                    <div class="alert alert-danger" role="alert">
                        User with email already exist!
                    </div>
                ';
            } else {
                // clean the form data before sending to database
                \$_first_name = mysqli_real_escape_string(\$connection, \$firstname);
                \$_last_name = mysqli_real_escape_string(\$connection, \$lastname);
                \$_email = mysqli_real_escape_string(\$connection, \$email);
                \$_mobile_number = mysqli_real_escape_string(\$connection, \$mobilenumber);
                \$_password = mysqli_real_escape_string(\$connection, \$password);
                // perform validation
                if(!preg_match("/^[a-zA-Z ]*\$/", \$_first_name)) {
                    \$f_NameErr = '<div class="alert alert-danger">
                            Only letters and white space allowed.
                        </div>';
                }
                if(!preg_match("/^[a-zA-Z ]*\$/", \$_last_name)) {
                    \$l_NameErr = '<div class="alert alert-danger">
                            Only letters and white space allowed.
                        </div>';
                }
                if(!filter_var(\$_email, FILTER_VALIDATE_EMAIL)) {
                    \$_emailErr = '<div class="alert alert-danger">
                            Email format is invalid.
                        </div>';
                }
                if(!preg_match("/^[0-9]{10}+\$/", \$_mobile_number)) {
                    \$_mobileErr = '<div class="alert alert-danger">
                            Only 10-digit mobile numbers allowed.
                        </div>';
                }
                if(!preg_match("/^(?=.*\d)(?=.*[@#\-_\$%^&+=§!\?])(?=.*[a-z])(?=.*[A-Z])[0-9A-Za-z@#\-_\$%^&+=§!\?]{6,20}\$/", \$_password)) {
                    \$_passwordErr = '<div class="alert alert-danger">
                             Password should be between 6 to 20 charcters long, contains atleast one special chacter, lowercase, uppercase and a digit.
                        </div>';
                }
                // Store the data in db, if all the preg_match condition met
                if((preg_match("/^[a-zA-Z ]*\$/", \$_first_name)) && (preg_match("/^[a-zA-Z ]*\$/", \$_last_name)) &&
                 (filter_var(\$_email, FILTER_VALIDATE_EMAIL)) && (preg_match("/^[0-9]{10}+\$/", \$_mobile_number)) && 
                 (preg_match("/^(?=.*\d)(?=.*[@#\-_\$%^&+=§!\?])(?=.*[a-z])(?=.*[A-Z])[0-9A-Za-z@#\-_\$%^&+=§!\?]{8,20}\$/", \$_password))){
                    // Generate random activation token
                    \$token = md5(rand().time());
                    // Password hash
                    \$password_hash = password_hash(\$password, PASSWORD_BCRYPT);
                    // Query
                    \$sql = "INSERT INTO users (firstname, lastname, email, mobilenumber, password, token, is_active,
                    date_time) VALUES ('{\$firstname}', '{\$lastname}', '{\$email}', '{\$mobilenumber}', '{\$password_hash}', 
                    '{\$token}', '0', now())";
                    // Create mysql query
                    \$sqlQuery = mysqli_query(\$connection, \$sql);
                    if(!\$sqlQuery){
                        die("MySQL query failed!" . mysqli_error(\$connection));
                    } 
                    // Send verification email
                    if(\$sqlQuery) {
                        \$msg = 'Click on the activation link to verify your email. <br><br>
                          <a href="http://${IP_ADDRESS}:80/php-user-authentication/user_verificaiton.php?token='.\$token.'"> Click here to verify email</a>
                        ';
                        // Create the Transport
                        \$transport = (new Swift_SmtpTransport('smtp.gmail.com', 465, 'ssl'))
                        ->setUsername('your_email@gmail.com')
                        ->setPassword('your_email_password');
                        // Create the Mailer using your created Transport
                        \$mailer = new Swift_Mailer(\$transport);
                        // Create a message
                        \$message = (new Swift_Message('Please Verify Email Address!'))
                        ->setFrom([\$email => \$firstname . ' ' . \$lastname])
                        ->setTo(\$email)
                        ->addPart(\$msg, "text/html")
                        ->setBody('Hello! User');
                        // Send the message
                        \$result = \$mailer->send(\$message);
                        if(!\$result){
                            \$email_verify_err = '<div class="alert alert-danger">
                                    Verification email coud not be sent!
                            </div>';
                        } else {
                            \$email_verify_success = '<div class="alert alert-success">
                                Verification email has been sent!
                            </div>';
                        }
                    }
                }
            }
        } else {
            if(empty(\$firstname)){
                \$fNameEmptyErr = '<div class="alert alert-danger">
                    First name can not be blank.
                </div>';
            }
            if(empty(\$lastname)){
                \$lNameEmptyErr = '<div class="alert alert-danger">
                    Last name can not be blank.
                </div>';
            }
            if(empty(\$email)){
                \$emailEmptyErr = '<div class="alert alert-danger">
                    Email can not be blank.
                </div>';
            }
            if(empty(\$mobilenumber)){
                \$mobileEmptyErr = '<div class="alert alert-danger">
                    Mobile number can not be blank.
                </div>';
            }
            if(empty(\$password)){
                \$passwordEmptyErr = '<div class="alert alert-danger">
                    Password can not be blank.
                </div>';
            }            
        }
    }
?>
EOF
        fi
    elif [[ $command == "signup.php" ]];then
        read -p "$command?"$'\n?' confirmation   </dev/tty
        if [[ "$confirmation" == "y" ]]; then
cat > $PHP_SCRIPTS_PATH/$command <<-EOF
<?php include('./controllers/register.php'); ?>
<!doctype html>
<html lang="en">
<head>
    <meta charset="utf-8">
    <meta name="viewport" content="width=device-width, initial-scale=1, shrink-to-fit=no">
    <link rel="stylesheet" href="https://stackpath.bootstrapcdn.com/bootstrap/4.5.0/css/bootstrap.min.css">
    <link rel="stylesheet" href="./css/style.css">
    <title>PHP User Registration System Example</title>
    <!-- jQuery + Bootstrap JS -->
    <script src="https://ajax.googleapis.com/ajax/libs/jquery/3.5.1/jquery.min.js"></script>
    <script src="https://stackpath.bootstrapcdn.com/bootstrap/4.5.0/js/bootstrap.min.js"></script></head>
<body>
   <?php include('./header.php'); ?>
    <div class="App">
        <div class="vertical-center">
            <div class="inner-block">
                <form action="" method="post">
                    <h3>Register</h3>
                    <?php echo \$success_msg; ?>
                    <?php echo \$email_exist; ?>
                    <?php echo \$email_verify_err; ?>
                    <?php echo \$email_verify_success; ?>
                    <div class="form-group">
                        <label>First name</label>
                        <input type="text" class="form-control" name="firstname" id="firstName" />
                        <?php echo \$fNameEmptyErr; ?>
                        <?php echo \$f_NameErr; ?></div>
                    <div class="form-group">
                        <label>Last name</label>
                        <input type="text" class="form-control" name="lastname" id="lastName" />
                        <?php echo \$l_NameErr; ?>
                        <?php echo \$lNameEmptyErr; ?></div>
                    <div class="form-group">
                        <label>Email</label>
                        <input type="email" class="form-control" name="email" id="email" />
                        <?php echo \$_emailErr; ?>
                        <?php echo \$emailEmptyErr; ?></div>
                    <div class="form-group">
                        <label>Mobile</label>
                        <input type="text" class="form-control" name="mobilenumber" id="mobilenumber" />
                        <?php echo \$_mobileErr; ?>
                        <?php echo \$mobileEmptyErr; ?></div>
                    <div class="form-group">
                        <label>Password</label>
                        <input type="password" class="form-control" name="password" id="password" />
                        <?php echo \$_passwordErr; ?>
                        <?php echo \$passwordEmptyErr; ?></div>
                    <button type="submit" name="submit" id="submit" class="btn btn-outline-primary btn-lg btn-block">Sign up
                    </button>
                </form>
            </div>
        </div>
    </div>
</body>
</html>
EOF
        fi
        
    elif [[ $command == "controllers/user_activation.php" ]];then
        read -p "$command?"$'\n?' confirmation   </dev/tty
        if [[ "$confirmation" == "y" ]]; then        
            mkdir -vp $PHP_SCRIPTS_PATH/controllers
cat > $PHP_SCRIPTS_PATH/$command <<-EOF
<?php
    // Database connection
    include('./config/db.php');
    global \$email_verified, \$email_already_verified, \$activation_error;
    // GET the token = ?token
    if(!empty(\$_GET['token'])){
       \$token = \$_GET['token'];
    } else {
        \$token = "";
    }
    if(\$token != "") {
        \$sqlQuery = mysqli_query(\$connection, "SELECT * FROM users WHERE token = '\$token' ");
        \$countRow = mysqli_num_rows(\$sqlQuery);
        if(\$countRow == 1){
            while(\$rowData = mysqli_fetch_array(\$sqlQuery)){
                \$is_active = \$rowData['is_active'];
                  if(\$is_active == 0) {
                     \$update = mysqli_query(\$connection, "UPDATE users SET is_active = '1' WHERE token = '\$token' ");
                       if(\$update){
                           \$email_verified = '<div class="alert alert-success">
                                  User email successfully verified!
                                </div>
                           ';
                       }
                  } else {
                        \$email_already_verified = '<div class="alert alert-danger">
                               User email already verified!
                            </div>
                        ';
                  }
            }
        } else {
            \$activation_error = '<div class="alert alert-danger">
                    Activation error!
                </div>
            ';
        }
    }
?>
EOF
        fi
    elif [[ $command == "user_verification.php" ]];then
        read -p "$command?"$'\n?' confirmation   </dev/tty
        if [[ "$confirmation" == "y" ]]; then
cat > $PHP_SCRIPTS_PATH/$command <<-EOF
<?php include('./controllers/user_activation.php'); ?>
<!doctype html>
<html lang="en">
<head>
    <meta charset="utf-8">
    <meta name="viewport" content="width=device-width, initial-scale=1, shrink-to-fit=no">
    <link rel="stylesheet" href="https://stackpath.bootstrapcdn.com/bootstrap/4.5.0/css/bootstrap.min.css">
    <link rel="stylesheet" href="./css/style.css">
    <title>User Verification</title>
    <!-- jQuery + Bootstrap JS -->
    <script src="https://ajax.googleapis.com/ajax/libs/jquery/3.5.1/jquery.min.js"></script>
    <script src="https://stackpath.bootstrapcdn.com/bootstrap/4.5.0/js/bootstrap.min.js"></script>
</head>
<body>
    <div class="container">
        <div class="jumbotron text-center">
            <h1 class="display-4">User Email Verification Demo</h1>
            <div class="col-12 mb-5 text-center">
                <?php echo \$email_already_verified; ?>
                <?php echo \$email_verified; ?>
                <?php echo \$activation_error; ?></div>
            <p class="lead">If user account is verified then click on the following button to login.</p>
            <a class="btn btn-lg btn-success" href="http://${IP_ADDRESS}:80/php-user-authentication/index.php">Click to Login</a>
        </div>
    </div>
</body>
</html>
EOF
        fi

    elif [[ $command == "controllers/login.php" ]];then
        read -p "$command?"$'\n?' confirmation   </dev/tty
        if [[ "$confirmation" == "y" ]]; then
cat > $PHP_SCRIPTS_PATH/$command <<-EOF            
<?php
    // Database connection
    include('config/db.php');
    global \$wrongPwdErr, \$accountNotExistErr, \$emailPwdErr, \$verificationRequiredErr, \$email_empty_err, \$pass_empty_err;
    if(isset(\$_POST['login'])) {
        \$email_signin        = \$_POST['email_signin'];
        \$password_signin     = \$_POST['password_signin'];
        // clean data 
        \$user_email = filter_var(\$email_signin, FILTER_SANITIZE_EMAIL);
        \$pswd = mysqli_real_escape_string(\$connection, \$password_signin);
        // Query if email exists in db
        \$sql = "SELECT * From users WHERE email = '{\$email_signin}' ";
        \$query = mysqli_query(\$connection, \$sql);
        \$rowCount = mysqli_num_rows(\$query);
        // If query fails, show the reason 
        if(!\$query){
           die("SQL query failed: " . mysqli_error(\$connection));
        }
        if(!empty(\$email_signin) && !empty(\$password_signin)){
            if(!preg_match("/^(?=.*\d)(?=.*[@#\-_\$%^&+=§!\?])(?=.*[a-z])(?=.*[A-Z])[0-9A-Za-z@#\-_\$%^&+=§!\?]{6,20}\$/", \$pswd)) {
                \$wrongPwdErr = '<div class="alert alert-danger">
                        Password should be between 6 to 20 charcters long, contains atleast one special chacter, lowercase, uppercase and a digit.
                    </div>';
            }
            // Check if email exist
            if(\$rowCount <= 0) {
                \$accountNotExistErr = '<div class="alert alert-danger">
                        User account does not exist.
                    </div>';
            } else {
                // Fetch user data and store in php session
                while(\$row = mysqli_fetch_array(\$query)) {
                    \$id            = \$row['id'];
                    \$firstname     = \$row['firstname'];
                    \$lastname      = \$row['lastname'];
                    \$email         = \$row['email'];
                    \$mobilenumber   = \$row['mobilenumber'];
                    \$pass_word     = \$row['password'];
                    \$token         = \$row['token'];
                    \$is_active     = \$row['is_active'];
                }
                // Verify password
                \$password = password_verify(\$password_signin, \$pass_word);
                // Allow only verified user
                if(\$is_active == '1') {
                    if(\$email_signin == \$email && \$password_signin == \$password) {
                       header("Location: ./dashboard.php");
                       \$_SESSION['id'] = \$id;
                       \$_SESSION['firstname'] = \$firstname;
                       \$_SESSION['lastname'] = \$lastname;
                       \$_SESSION['email'] = \$email;
                       \$_SESSION['mobilenumber'] = \$mobilenumber;
                       \$_SESSION['token'] = \$token;
                    } else {
                        \$emailPwdErr = '<div class="alert alert-danger">
                                Either email or password is incorrect.
                            </div>';
                    }
                } else {
                    \$verificationRequiredErr = '<div class="alert alert-danger">
                            Account verification is required for login.
                        </div>';
                }
            }
        } else {
            if(empty(\$email_signin)){
                \$email_empty_err = "<div class='alert alert-danger email_alert'>
                            Email not provided.
                    </div>";
            }
            if(empty(\$password_signin)){
                \$pass_empty_err = "<div class='alert alert-danger email_alert'>
                            Password not provided.
                        </div>";
            }            
        }
    }
?>
EOF
        fi   
    elif [[ $command == "controllers/index.php" ]];then
        read -p "$command?"$'\n?' confirmation   </dev/tty
        if [[ "$confirmation" == "y" ]]; then
cat > $PHP_SCRIPTS_PATH/$command <<-EOF            
<!doctype html>
<html lang="en">
<head>
    <meta charset="utf-8">
    <meta name="viewport" content="width=device-width, initial-scale=1, shrink-to-fit=no">
    <link rel="stylesheet" href="https://stackpath.bootstrapcdn.com/bootstrap/4.5.0/css/bootstrap.min.css">
    <link rel="stylesheet" href="css/style.css">
    <title>PHP User Registration & Login System Demo</title>
    <!-- jQuery + Bootstrap JS -->
    <script src="https://ajax.googleapis.com/ajax/libs/jquery/3.5.1/jquery.min.js"></script>
    <script src="https://stackpath.bootstrapcdn.com/bootstrap/4.5.0/js/bootstrap.min.js"></script>
</head>
<body>
    <!-- Header -->
    <?php include('../php-user-authentication/header.php'); ?>
    <!-- Login script -->
    <?php include('./controllers/login.php'); ?>
    <!-- Login form -->
    <div class="App">
        <div class="vertical-center">
            <div class="inner-block">
                <form action="" method="post">
                    <h3>Login</h3>
                    <?php echo \$accountNotExistErr; ?>
                    <?php echo \$emailPwdErr; ?>
                    <?php echo \$verificationRequiredErr; ?>
                    <?php echo \$email_empty_err; ?>
                    <?php echo \$pass_empty_err; ?>
                    <div class="form-group">
                        <label>Email</label>
                        <input type="email" class="form-control" name="email_signin" id="email_signin" /></div>
                    <div class="form-group">
                        <label>Password</label>
                        <input type="password" class="form-control" name="password_signin" id="password_signin" />
                    </div>
                    <button type="submit" name="login" id="sign_in" class="btn btn-outline-primary btn-lg btn-block">Sign in</button>
                </form>
            </div>
        </div>
    </div>
</body>
</html>
EOF
        fi
    elif [[ $command == "dashboard.php" ]];then
        read -p "$command?"$'\n?' confirmation   </dev/tty
        if [[ "$confirmation" == "y" ]]; then
cat > $PHP_SCRIPTS_PATH/$command <<-EOF            
<?php include('config/db.php'); ?>
<!doctype html>
<html lang="en">
<head>
    <meta charset="utf-8">
    <meta name="viewport" content="width=device-width, initial-scale=1, shrink-to-fit=no">
    <link rel="stylesheet" href="https://stackpath.bootstrapcdn.com/bootstrap/4.5.0/css/bootstrap.min.css">
    <link rel="stylesheet" href="./css/style.css">
    <title>PHP User Registration System Example</title>
    <!-- jQuery + Bootstrap JS -->
    <script src="https://ajax.googleapis.com/ajax/libs/jquery/3.5.1/jquery.min.js"></script>
    <script src="https://stackpath.bootstrapcdn.com/bootstrap/4.5.0/js/bootstrap.min.js"></script>
</head>
<body>
    <div class="container mt-5">
        <div class="d-flex justify-content-center">
            <div class="card" style="width: 25rem">
                <div class="card-body">
                    <h5 class="card-title text-center mb-4">User Profile</h5>
                    <h6 class="card-subtitle mb-2 text-muted"><?php echo \$_SESSION['firstname']; ?>
                        <?php echo \$_SESSION['lastname']; ?></h6>
                    <p class="card-text">Email address: <?php echo \$_SESSION['email']; ?></p>
                    <p class="card-text">Mobile number: <?php echo \$_SESSION['mobilenumber']; ?></p>          
                    <a class="btn btn-danger btn-block" href="logout.php">Log out</a>
                </div>
            </div>
        </div>
    </div>
</body>
</html>
EOF
        fi
    elif [[ $command == "logout.php" ]];then
        read -p "$command?"$'\n?' confirmation   </dev/tty
        if [[ "$confirmation" == "y" ]]; then
cat > $PHP_SCRIPTS_PATH/$command <<-EOF            
<?php     
    session_start();
    session_destroy();
    header("Location: http://${IP_ADDRESS}:80/php-user-authentication/index.php")
;?>
EOF
        fi
        
        
        
        
    # elif [[ $command == "lib/plugins" ]];then
    #     read -p "$command?"$'\n?' confirmation   </dev/tty
    #     if [[ "$confirmation" == "y" ]]; then
    #         $command
    #     fi
        
    # elif [[ $command == "header.php" ]];then
    #     read -p "$command?"$'\n?' confirmation   </dev/tty
    #     if [[ "$confirmation" == "y" ]]; then
    #         $command
    #     fi
        
        
    # elif [[ $command == "package" ]];then
    #     read -p "$command?"$'\n?' confirmation   </dev/tty
    #     if [[ "$confirmation" == "y" ]]; then
    #         $command
    #     fi
    else
        printf "skipping $command"
    fi
done

# curl -I http://$IP_ADDRESS:80
# sudo unlink /etc/nginx/sites-enabled/default
# nano  /var/log/nginx/error.log
# sudo apt-get purge nginx nginx-common