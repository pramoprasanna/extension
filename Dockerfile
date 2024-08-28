# Use an official Python runtime as a parent image
FROM python:3.12-alpine

# Set the working directory in the container
WORKDIR /app

# Copy the current directory contents into the container at /app
COPY . /app

# Upgrade pip to the latest version
RUN pip install --upgrade pip

# Install virtualenv
RUN pip install virtualenv

# Create and activate a virtual environment
RUN python -m venv venv
RUN . venv/bin/activate

# Install any necessary dependencies specified in requirements.txt
RUN venv/bin/pip install -r requirements.txt

# Make port 8080 available to the world outside this container
EXPOSE 8080

# Define environment variable
ENV NAME World

# Run app.py when the container launches
CMD ["venv/bin/python", "app.py"]
