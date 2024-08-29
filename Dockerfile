# Use an official Python runtime as a parent image
FROM python:3.12

# Set the working directory in the container
WORKDIR /app

# Copy the current directory contents into the container at /app
COPY . /app

# Create a virtual environment
RUN python -m venv venv

# Install any necessary dependencies specified in requirements.txt
RUN venv/bin/pip install --upgrade pip setuptools wheel
RUN venv/bin/pip install -r requirements.txt

# Make port 8080 available to the world outside this container
EXPOSE 8080

# Define environment variable
ENV NAME World

# Run the application
CMD ["venv/bin/python", "server.py"]
