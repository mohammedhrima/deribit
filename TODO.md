Slide 1: Introduction
    Title: Who Am I

    Brief introduction (your name, background, and interest in the role).
    Mention that the project is part of the GoQuant recruitment process.

Slide 2: Goal of the Project
    Title: Objective

    Build a high-performance Order Execution and Management System to trade on Deribit Test.
    Align with GoQuant’s requirements for low-latency, robust, and scalable systems.

Slide 3: Requirements
    Title: Core Features
    Order Management Functions:

    Authentication.
    Place, modify, and cancel orders.
    Get order book and positions.
    Real-Time Market Data:

    WebSocket streaming for live market data.

    Technical Challenges:
        Low-latency performance.
        Multi-client support.
        Error handling and efficient resource management.

Slide 5: Challenges and My Solution
    Title: Problem and Solution

    Identified Problem:
        Most implementations rely solely on CLI tools.
        Lack of a user-friendly interface.
        
    My Solution:
        create a web-based UI by enabling static file serving through the webserver.

Slide 4: Project Plan
    Title: Steps to Implementation

    Step 1: Build a C++ codebase interacting with the Deribit API.
    Step 2: Create a WebSocket server for streaming real-time market data.
    Step 3: Integrate a webserver to serve static files and process API requests.


Slide 6: Technologies Used
    Title: Tech Stack

    Language: C++.
    Libraries:
        OpenSSL (for secure connections).
        NLohmann JSON (for parsing JSON responses).

Slide 7: Project Showcase
    Title: Code Review and Demonstration

    Client Component:

        Handles authentication and communication with the Deribit API.
        Fetches order book and positions.

        Webserver Implementation:
            Uses epoll for high-performance multiplexing.

        Request Handling:
            /api: Forwards requests to the Deribit API, processes the response, and sends it back to the client.
            Static files: Serves files if they exist; otherwise, returns an error.

        Integration:
            Combines the WebSocket server and webserver to enable a seamless user experience.

Slide 8: Problem Solving and Optimization
    Title: Performance and Scalability

    Optimization Techniques:
        Epoll for handling concurrent client connections.
        Reduced JSON parsing overhead using NLohmann JSON.

    Title: Final Thoughts
        Demonstrated ability to meet GoQuant’s requirements.
        Enhanced user experience with a web-based UI.
        Prioritized performance, scalability, and maintainability.

Slide 9: Closing
    Title: Thank You!

