# Beeper Dashboard

## Project Overview

Beeper Dashboard is a web application that provides a user interface for managing and monitoring various bridges associated with a Beeper account. It allows users to view detailed information about their account, bridges, and perform actions such as resetting passwords, deleting bridges, and posting bridge states.

## Installation Instructions

To set up the Beeper Dashboard project, follow these steps:

1. Clone the repository:
   ```bash
   git clone https://github.com/cameronaaron/beeperdash.git
   cd beeperdash
   ```

2. Create a virtual environment and activate it:
   ```bash
   python3 -m venv venv
   source venv/bin/activate
   ```

3. Install the required dependencies:
   ```bash
   pip install -r requirements.txt
   ```

4. Set up environment variables:
   Create a `.env` file in the project root directory and add the following environment variables:
   ```plaintext
   GITHUB_TOKEN=<your_github_token>
   ```

5. Run the application:
   ```bash
   uvicorn main:app --reload
   ```

## Usage Instructions

To use the Beeper Dashboard, follow these steps:

1. Open your web browser and navigate to `http://127.0.0.1:8000`.

2. Login with your Beeper account email.

3. Enter the challenge code sent to your email.

4. Once logged in, you will be redirected to the dashboard where you can view and manage your bridges.

## Contribution Guidelines

We welcome contributions to the Beeper Dashboard project. To contribute, follow these steps:

1. Fork the repository on GitHub.

2. Create a new branch for your feature or bugfix:
   ```bash
   git checkout -b my-feature-branch
   ```

3. Make your changes and commit them with a descriptive commit message:
   ```bash
   git commit -am "Add new feature"
   ```

4. Push your changes to your forked repository:
   ```bash
   git push origin my-feature-branch
   ```

5. Create a pull request on the original repository and describe your changes in detail.

6. Wait for the project maintainers to review your pull request. They may request changes or provide feedback.

Thank you for contributing to the Beeper Dashboard project!
