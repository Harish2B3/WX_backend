# Backend

This directory contains the Node.js backend service for WormX Drive.

## Setup

This backend uses a database and a file storage service, which require environment variables for configuration.

1.  **Create Environment File:**
    In this `backend` directory, create a new file named `.env` by copying the example file:
    ```bash
    cp .env.example .env
    ```

2.  **Configure Variables:**
    Open the newly created `.env` file and fill in the values:

    *   `DB_URI`: Your Database connection string. This is required.
    *   `JWT_SECRET`: A long, random, and secret key used for signing authentication tokens. This is required for security.
    *   `BOT_TOKEN`: Your File Storage Service Bot Token, used for uploading and downloading files. This is required.
    *   `CHAT_ID`: The File Storage Service Channel ID where the bot will store all uploaded files. This is required.

    Your `.env` file should look like this (with your actual credentials):
    ```
    DB_URI=your-database-connection-string-here
    JWT_SECRET=your-super-secret-and-long-jwt-key-that-is-hard-to-guess
    BOT_TOKEN=123456:ABC-DEF1234ghIkl-zyx57W2v1u123ew11
    CHAT_ID=-1003435847065
    ```

3.  **Set up Database:**
    If you are running locally, make sure you have a running instance of your chosen database. You can also use a cloud database service and put its connection string in `DB_URI`.


## Running the Backend

1.  **Install dependencies:**
    Navigate to this directory in your terminal and run:
    ```bash
    npm install
    ```

2.  **Start the server:**
    ```bash
    npm start
    ```

The server will connect to your database and will be running at `http://localhost:3001`. Users can register and log in through the frontend application.