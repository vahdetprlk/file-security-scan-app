## File Security Scan Application

The Security Scan Application is watch a directory and its subdirectories for changes and scan by using VirusTotal API.
And store results in a directory as text files.

### Installation and Usage

1. Clone the repository.
2. Navigate to the repository directory.
3. Add your VirusTotal API key in the **.env** file. (You can get an API key from [VirusTotal](https://www.virustotal.com/gui/join-us))
4. Run the **'docker-compose up'** command
5. The application is now operational.
6. Enter in the "*watch-directory*" container by running '**docker exec -it watch-directory bash**' command.
7. Add files or directories containing files to the "**/watch_data**" directory.
8. The application will scan the files and store the results in the "**/results**" directory. (This will take some time depending the API response time.)

#### NOTE: Tests, logs, and example results are located in the "**/test_results**" directory.
