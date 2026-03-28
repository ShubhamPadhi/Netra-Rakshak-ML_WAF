# Use Python 3.9 as the base image
FROM python:3.9-slim

# Set the working directory inside the container to /app
WORKDIR /app

# 1. Install system tools (needed for building some python libraries)
RUN apt-get update && apt-get install -y \
    build-essential \
    curl \
    && rm -rf /var/lib/apt/lists/*

# 2. Copy the requirements file from your computer to the container
COPY requirements.txt .

# 3. Install Python dependencies
RUN pip install --no-cache-dir -r requirements.txt

# 4. Copy YOUR ENTIRE PROJECT folder structure into the container
# This copies backend/, certs/, models/, dashboard/ exactly as they are.
COPY . .

# 5. Expose the ports for Backend (5000) and Dashboard (8501)
EXPOSE 5000
EXPOSE 8501

# 6. Make the start script executable
RUN chmod +x start.sh

# 7. The command that runs when the container starts
CMD ["./start.sh"]