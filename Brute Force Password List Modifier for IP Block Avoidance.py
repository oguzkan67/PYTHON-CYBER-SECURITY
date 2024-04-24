with open(r"C:\Users\MOSTER\Desktop\TENGRI.txt", "r") as f:                    # Open the file in read mode
          #write the location of the file filled with password                 # Read the contents of the file
                                                                               #lines = f.read()
    lines = f.readlines()
         #write the location of the file that contains the configured passwords                                        
with open(r"C:\Users\MOSTER\Desktop\GOKBÖRÜ.txt", "w") as f:           # Open the file in write mode and append
    for line in lines:                                                 # Loop through each line
        f.write(line.strip() + "\n")                                   # Write the line without the newline character
        f.write("WORD\n")     # Insert "WORD" after each line you can change it according to your correct password
        
                                                                       # THIS CODE CAN BE USED TO CONFIGURE PASSWORD LISTS TO AVOID FROM THE IP BLOCK DURING THE BRUTE FORCE ATTEMPTS TO A TARGET
                                                                       # ALSO CAN BE USED FOR THE WEB SECURITY ACADEMY IP BLOCKING BRUTE FORCE TASK.
