# Beeper Dashboard (Unofficial)

Created by Cameron Aaron

⚠️ **IMPORTANT DISCLAIMER**
- This is an **unofficial** dashboard for Beeper
- Not affiliated with, endorsed by, or supported by Beeper or Automattic
- Use at your own risk
- This software interacts with Beeper's APIs independently

## About
A dashboard for monitoring and managing Beeper bridges, providing version tracking, status monitoring, and bridge management capabilities.

## Features
- Monitor bridge status and versions
- Track version updates
- Manage bridge configurations
- View detailed bridge information
- Check connection status

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

## Author
Cameron Aaron
- GitHub: [@cameronaaron](https://github.com/cameronaaron)

## License
MIT License - See LICENSE file for details
