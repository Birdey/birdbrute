# BirdBrute

Will brute force any specific url for you that you define in the command.
It will use the wordlist (words.txt) and will try to brute the url with each word in the wordlist.
It  check for files of extentions .php, .html for all words in the wordlist.
It  check for subdomains with the words in the wordlist.

## Installation

    ```sh
    git clone https://github.com/Birdey/birdbrute.git 
    cd birdbrute
    pip3 install -r requirements.txt
    ```

## Usage

The base command is

    ```sh
    phyton3 Brute.py "URL"
    ```

## Dependencies

- requests
- bs4
- sys
- time
- datetime

## Planned

- More features coming soon :)

## Example

    ```sh
    phyton3 Brute.py "google.com"
    ```

## Known bugs

- When the url is not returning 404 and size of the "404" page varies, it will think the site is found. (Can be fixed in a later release)

## License

Copyright (c) 2023, Christoffer von Matérn. (MIT License)
