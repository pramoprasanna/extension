backend
|
|-- routes
|       |--auth.py
|--models.py
|--server.py
|--utils.py"# Chrome-Extension" 


Create ECR Repository

Create IAM User : extension-users : AKIAVY2PGZMEZGZHPSWQ >  uVaEmo6A5Tl3+J49cnt6KRIEN9iUtSj8J1gt1u8M

Create EC2 Instance and Install Docker 

Create Runner on Github portal - and run the commans mentioend in the Github on your EC2 Instance

Add all Secret Environement variables declared in main.yaml file 

AWS_ACCESS_KEY_ID : IAM USer AKIAVY2PGZMERX3X74HK  > AWS_SECRET_ACCESS_KEY: 8rFR2DxiP1RlVmUs2hbL+af2TsPYzxvWR90DE5xJ ( IAM User  )

AWS_REGION : ap-southeast-2

AWS_ECR_LOGIN_URI : 396913724169.dkr.ecr.ap-southeast-2.amazonaws.com

ECR_REPOSITORY_NAME : thinkinfo/extension

New EC2 Instance Setup :

Docker Setup in EC2:

sudo apt-get update -y
sudo apt-get upgrade

#required

curl -fsSL https://get.docker.com -o get-docker.sh
sudo sh get-docker.sh
sudo usermod -aG docker ubuntu
newgrp docker

Runner Setup in the EC2 Instance to Listen to GIT Updates:

ONE TIME :

# Download the latest runner package

STEP 1 : $ mkdir actions-runner && cd actions-runner
STEP 2: $ curl -o actions-runner-linux-x64-2.319.1.tar.gz -L https://github.com/actions/runner/releases/download/v2.319.1/actions-runner-linux-x64-2.319.1.tar.gz# Optional: Validate the hash
STEP 3: $ echo "3f6efb7488a183e291fc2c62876e14c9ee732864173734facc85a1bfb1744464  actions-runner-linux-x64-2.319.1.tar.gz" | shasum -a 256 -c# Extract the installer
STEP 4: $ tar xzf ./actions-runner-linux-x64-2.319.1.tar.gz
STEP 5: ./config.sh --url https://github.com/pramoprasanna/extension --token << Gets Updated , Check the Actions > Runner Tab in the GIT REPO >>

To activate GitHub Runner on existing server :

./run.sh

Resolved Space issue failure "failed to register layer: write /app/venv/lib/python3.12/site-packages/opencv_python.libs/libopenblas-r0-f650aae0.3.3.so: no space left on device" with below steps :

Extend the EBS volume: If cleaning up space doesn't help and you anticipate needing more space, you can extend the EBS volume attached to your instance:

In the AWS Management Console, go to the EC2 Dashboard > Volumes.
Find the volume attached to your instance and select Modify Volume to increase the size.
After increasing the size, you'll need to extend the partition on the instance:

sudo growpart /dev/xvda 1
sudo resize2fs /dev/xvda1
