import os
import mimetypes
import datetime
import pytz
import asyncio
import aiohttp
from watchdog.observers import Observer
from watchdog.events import FileSystemEventHandler


class VirusTotalHandler():
    def __init__(self, path_to_results):
        self.path_to_results = path_to_results
        self.url = "https://www.virustotal.com/api/v3/files"
        self.headers = {
            "accept": "application/json",
            "x-apikey": os.getenv("VIRUS_TOTAL_API_KEY")
        }

    async def check(self, file_path):
        """
        Uploads the file added to 'path_to_watch' to the VirusTotal API
        for analysis. And handles the response. Save to 'path_to_results'
        directory if response OK (200).

        Args:
            file_path (str): The path of the file to be analyzed.
        """
        mimetype, _ = mimetypes.guess_type(file_path)

        file = aiohttp.FormData()

        file.add_field("file",
                       open(file_path, "rb"),
                       filename=file_path,
                       content_type=mimetype)
        async with aiohttp.ClientSession() as session:
            async with session.post(self.url,
                                    data=file,
                                    headers=self.headers) as response:
                if response.status == 200:
                    data = await response.json()
                    analysis_url = data['data']['links']['self']
                    print(f"File uploaded to API: {file_path}")
                    result_response = await self.get_analysis(file_path,
                                                              analysis_url,
                                                              session)
                    if result_response is not None:
                        await self.result_save(result_response, file_path)
                elif response.status == 413:
                    print("File too large to upload to"
                          f"VirusTotal: {file_path}")
                    return
                else:
                    error_message = await response.json()
                    print("An error occurred:",
                          error_message['error']['message'])
                    return

    async def get_analysis(self, file_path, analysis_url, session):
        """
        Performs a GET request to retrieve the result of the analysis.

        Args:
            file_path (str): The target directory for saving the result file.
            analysis_url (str): The endpoint URL to retrieve the analysis
            result.
            session (aiohttp.ClientSession): The active session for making
            API requests.

        Returns:
            aiohttp.ClientResponse: The response object if the status
            is 200 (OK).
            None: If the status is not 200 after the maximum number of retries.
        """
        interval = int(os.getenv('GET_REPORTS_INTERVAL'))
        max_retries = int(os.getenv('GET_REPORTS_MAX_RETRIES'))
        retry_count = 0

        while retry_count < max_retries:
            async with session.get(analysis_url,
                                   headers=self.headers) as response:
                if response.status == 200:
                    data = await response.json()
                    if data['data']['attributes']['status'] == 'completed':
                        print(f"Analysis complete succesfully: {file_path}")
                        return response
                else:
                    error_message = await response.json()
                    print("An error occurred:",
                          error_message['error']['message'])
            retry_count += 1
            print(f"Analysis queued: {file_path}")
            await asyncio.sleep(interval)
        print(f"An error occured: Maximum retry count reached: {file_path}")
        return None

    async def result_save(self, response, file_path):
        """
        Parse the successful response JSON from the VirusTotal API
        and creates a result file.

        Args:
            response (aiohttp.ClientResponse): The successful response
            object from the VirusTotal API
            file_path (str): Target directory for result file.
        """
        data = await response.json()
        results = data['data']['attributes']['results']
        stats = data["data"]["attributes"]["stats"]
        formatted_results = await self.format_result(data, results, stats)

        timestamp = datetime.datetime.now().strftime("%Y%m%d-%H%M%S.%f")[:-3]
        file_name = file_path.split("/")[-1]
        if file_name.startswith("."):
            file_name = file_name[1:]
        output_name = f"{file_name}-{timestamp}-results.txt"
        with open(f"{self.path_to_results}/{output_name}", "w") as result_file:
            result_file.write(formatted_results)

    async def format_result(self, data, results, stats):
        """
        Formats the results from the VirusTotal API response into
        a readable string.

        Args:
            data (dict): The JSON response data from the VirusTotal API.
            results (dict): Analysis results from API
            stats (dict): Containing statistical information
            about the analysis.

        Returns:
            str:  A formatted string representing the analysis results.
        """
        formatted_stats = ""
        for stat, value in stats.items():
            formatted_stats += f"{stat}: {value}\n"

        timestamp = data["data"]["attributes"]["date"]
        istanbul_tz = pytz.timezone('Europe/Istanbul')
        local_time = datetime.datetime.fromtimestamp(timestamp, istanbul_tz)

        formatted_results = ""
        formatted_results += f"Id: {data['data']['id']}\n"
        formatted_results += f"Last Analysis Date: {local_time}\n"
        formatted_results += "############################\n"
        formatted_results += f"Stats: \n{formatted_stats}\n"
        formatted_results += "############################\n"

        for _, result in results.items():
            formatted_results += f"Engine Name: {result['engine_name']}\n"
            formatted_results += f"Engine Version: {result['engine_version']}\n"
            formatted_results += f"Engine Update: {result['engine_update']}\n"
            formatted_results += f"Category: {result['category']}\n"
            formatted_results += f"Result: {result['result']}\n"
            formatted_results += "------------------------\n"

        metadata = data["meta"]["file_info"]
        formatted_results += "Metadata:\n"
        for key, value in metadata.items():
            formatted_results += f"{key}: {value}\n"
        return formatted_results


class EventHandler(FileSystemEventHandler):
    def __init__(self, path_to_results, event_loop):
        super().__init__()
        self.virus_total = VirusTotalHandler(path_to_results)
        self.loop = event_loop

    def on_created(self, event):
        """
        This function calls the check function to process
        the newly created file.

        Args:
            event (FileSystemEvent): Contains file system event information.
        """
        if event.is_directory is False:
            print(f"File Created: {event.src_path}")
            try:
                self.loop.create_task(self.virus_total.check(event.src_path))
            except Exception as e:
                print(f"Exception occurred in on_created - {e}")


async def main():
    """
    Sets up the event loop and observer to monitor the specified directory.
    The observer watches the 'path_to_watch' directory for new files.
    When a new file is created, it is checked using the VirusTotal API.
    The results of the analysis are saved in the 'path_to_results' directory.
    """

    path_to_watch = "/watch_data"
    path_to_results = "/results"
    event_loop = asyncio.get_event_loop()
    event_handler = EventHandler(path_to_results, event_loop)
    observer = Observer()
    observer.schedule(event_handler, path_to_watch, recursive=True)
    observer.start()

    try:
        while True:
            await asyncio.sleep(1)
    except KeyboardInterrupt:
        print("watching Stopped.")
        observer.stop()
    observer.join()

if __name__ == "__main__":
    asyncio.run(main())
