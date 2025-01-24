# Web Server API Tester

This project is designed to test endpoints of a web server API through an HTML interface. The application provides several pages, each dedicated to testing a specific endpoint.

## Prerequisites
- **Make** is required to run the provided commands.
- Ensure that port **17000** is available on your system.

## Installation and Usage

### Steps to Run the Project

1. **Install Dependencies**  
- Run the following command to install the necessary dependencies:
```bash
   make install
```
2. Compile the Project
- To compile the source code, run:
```bash
    make
```

3. Access the Application
- Open your browser and navigate to:
```bash
    http://localhost:17000
```

4. Pages Overview (check public directory)
- When running the application, you will see an HTML interface with links to navigate through the following pages:

- index.html:	 The main page of the application.
- cancel.html: Tests the Cancel endpoint of the API.
- login.html:	 Tests the Login endpoint of the API.
- modify.html: Tests the Modify endpoint of the API.
- order_book.html:	Tests the Order Book endpoint of the API.
- place.html:	Tests the Place endpoint of the API.
- position.html:	Tests the Position endpoint of the API.

