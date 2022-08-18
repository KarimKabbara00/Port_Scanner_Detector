require 'socket' #imports socket to establish connections

#connect to port function
def open_port(host, port)

        sock = Socket.new(:INET, :STREAM) #creates a socket for connection

          raw = Socket.pack_sockaddr_in port, host # combines the port and host to an AF_INET string

           puts "#{port} open." if sock.connect(raw) #if connection established, print

       rescue(Errno::ECONNREFUSED) # refused connection

          rescue(Errno::ETIMEDOUT) #timed out connection

end

#main function
def main(host, start_port, end_port)

          until start_port==end_port do #while loop until start_port = end_port

          open_port(host, start_port)   #call open_port with host and start port

          start_port +=1		#try the next port

          end

end


#call main with command line input
main ARGV[0], ARGV[1].to_i, ARGV[2].to_i