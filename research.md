# Questions

* Summarize the project, what it's goals are, and why it exists

        Firecracker is a lightweight virtual machine monitor designed with the goal of achieving the security benefits of virtualization without having to make the traditional sacrifice in performance. The project is being developed as a part of AWS and supports AWS Lambda serverless functions[1].

* What is the target domain of the system? Where is it valuable and where is it not a good fit? 

        Firecracker is being designed to support AWS lambda:[1]
        - IoT
        - Mobile/Web apps
        - request/response/event driven services
        - real time streaming/data processing
        - automation

# What are the modules of the System

* Client facing REST api receives requests from client module
    - The following code is called when the HTTP connection checks for a valid request

```rust
//rust note: match/some ~ switch/case

match find(&self.buffer[*start..end], &[CR, LF]) {
            Some(line_end_index) => {
                // The unchecked addition `start + line_end_index` is safe because `line_end_index`
                // is returned by `find` and thus guaranteed to be in-bounds. This also makes the
                // slice access safe.
                let line = &self.buffer[*start..(*start + line_end_index)];

                // The unchecked addition is safe because of the previous `find()`.
                *start = *start + line_end_index + CRLF_LEN;

                // Form the request with a valid request line, which is the bare minimum
                // for a valid request
                
                /*
                 * Ryan: Creates a wrapper around the incoming HTTP Request
                 * Append the minimum request to the handler's
                 * pending_request queue
                 */
                self.pending_request = Some(Request {
                    request_line: RequestLine::try_from(line)
                        .map_err(ConnectionError::ParseError)?,
                    headers: Headers::default(),
                    body: None,
                });
                self.state = ConnectionState::WaitingForHeaders;
                Ok(true)
            }
            None => {
                // The request line is longer than BUFFER_SIZE bytes, so the request is invalid.
                if end == BUFFER_SIZE && *start == 0 {
                    return Err(ConnectionError::ParseError(RequestError::InvalidRequest));
                } else {
                    // Move the incomplete request line to the beginning of the buffer and wait
                    // for the next `try_read` call to complete it.
                    // This can only happen if another request was sent before this one, as the
                    // limit for the length of a request line in this implementation is 1024 bytes.
                    self.shift_buffer_left(*start, end)
                        .map_err(ConnectionError::ParseError)?;
                }
                Ok(false)
            }
```

[Source](https://github.com/firecracker-microvm/firecracker/blob/main/src/micro_http/src/connection.rs) Lines 161-196

* The following pops this request off of the parsed requests queue for the HTTP connection and appends it to
        one associated with the client

```Rust
impl<T: Read + Write> ClientConnection<T> {
    /*Ryan: constructor for the HTTP connection associated with this Client
     *  self.connection refers to this struct
     */
    fn new(connection: HttpConnection<T>) -> Self {
        Self {
            connection,
            state: ClientConnectionState::AwaitingIncoming,
            in_flight_response_count: 0,
        }
    }

    fn read(&mut self) -> Result<Vec<Request>> {
        // Data came into the connection.
        let mut parsed_requests = vec![];
        match self.connection.try_read() {
            Err(ConnectionError::ConnectionClosed) => {
                // Connection timeout.
                self.state = ClientConnectionState::Closed;
                // We don't want to propagate this to the server and we will
                // return no requests and wait for the connection to become
                // safe to drop.
                return Ok(vec![]);
            }
            Err(ConnectionError::StreamError(inner)) => {
                // Reading from the connection failed.
                // We should try to write an error message regardless.
                let mut internal_error_response =
                    Response::new(Version::Http11, StatusCode::InternalServerError);
                internal_error_response.set_body(Body::new(inner.to_string()));
                self.connection.enqueue_response(internal_error_response);
            }
            Err(ConnectionError::ParseError(inner)) => {
                // An error occurred while parsing the read bytes.
                // Check if there are any valid parsed requests in the queue.
                while let Some(_discarded_request) = self.connection.pop_parsed_request() {}

                // Send an error response for the request that gave us the error.
                let mut error_response = Response::new(Version::Http11, StatusCode::BadRequest);
                error_response.set_body(Body::new(format!(
                    "{{ \"error\": \"{}\nAll previous unanswered requests will be dropped.\" }}",
                    inner.to_string()
                )));
                self.connection.enqueue_response(error_response);
            }
            Err(ConnectionError::InvalidWrite) => {
                // This is unreachable because `HttpConnection::try_read()` cannot return this error variant.
                unreachable!();
            }
            /*
             * Ryan: the above are all error cases, the loop below is the intended behavior
             *   removes the request from the connection (allowing it to listen for more requests), and place it 
             *   in the client struct's request queue to be dealt with later
             */
            Ok(()) => {
                while let Some(request) = self.connection.pop_parsed_request() {
                    // Add all valid requests to `parsed_requests`.
                    parsed_requests.push(request);
                }
            }
        }
```

[Source](https://github.com/firecracker-microvm/firecracker/blob/main/src/micro_http/src/server.rs) Lines 97 - 150




[1] https://www.usenix.org/system/files/nsdi20-paper-agache.pdf