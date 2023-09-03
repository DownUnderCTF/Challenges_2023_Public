crossed monkes
============

**Category:** web

**Difficulty:** hard

**Author:** ghostccamm

**Files:**
- [crossedmonkes.zip](./publish/crossedmonkes.zip)

**Ports Open:** 1337, 3000

Ghostccamm gave 24 monkes 4,200 cans of energy drinks and locked them in a basement to develop a *secure file sharing platform*.

After 3 days with no sleep, the monkes built this website. However, they are very **cross** for some reason.

To access the bot add `-bot` at the end of your challenge instance domain.

**Important!** When exploiting the challenge instance, use your instance hostname **not http://monkestorage:3000**!

Author: ghostccamm

---

## Solution

The goal is to achieve XSS on the website and retrieve the flag from `/flag` on the monkestorage site.

The first issue is that there are no CSRF security mechanisms. Therefore, you can trick a monke to upload a file by exploiting this CSRF vulnerability.

The second issue is that SVG files can be uploaded, that allow executing JavaScript. However, the SVG uploads are *sanitised* by being converted to a PNG file. Below is the code for parsing the SVG file.

```py
def convert_svg2png(filename: str):
    new_filename = os.path.splitext(filename)[0] + ".png"
    file_path = safe_join(STORAGE_PATH, filename)
    new_path = safe_join(STORAGE_PATH, new_filename)
    try:
        svg2png(
            url=file_path, write_to=new_path,
            parent_height=1024, parent_width=1024
        )
    finally:
        os.remove(file_path)
    return new_filename
```

The issue here is that the SVG is saved to the file system and is accessible if the MongoDB ObjectID for the SVG upload is known before the sanitisation process has completed. The `search` feature on the `/view/<string:share_key>` route would not work, since the entry for the SVG file does not have `published = True` until the SVG file has been sanitised. However, there is a XS leaks vulnerability that can be exploited to leak the Object ID of a file that has already been uploaded. 

The MongoDB ObjectID can be determined using the following process.

1. Upload any image file.
2. Exploit a XS Leaks vulnerability by using `/view/<string:share_key>?redirect_to=True&search=` to perform a regex match on `search_id` attr to leak the initial MongoDB ObjectID.
3. Using this initial ObjectID, the [*'random value generated once per process'*](https://www.mongodb.com/docs/manual/reference/method/ObjectId/) will be the same within a short time frame. Therefore the ObjectID for the SVG file can be predetermined.
4. Yeet the monke into the SVG file using `/view/<string:share_key>/<string:file_id>` that does not validate if the file has been `published` yet.

Exploit files:

1. [`csrf0.html`](./solve/csrf0.html): Uploads the first file when the button is clicked to get the initial ObjectID for predetermining the ObjectID of the SVG payload. Opens new tab to [`csrf1.html`](./solve/csrf1.html).
2. [`csrf1.html`](./solve/csrf1.html): Exploits the XS Leaks vulnerability to leak the ObjectID of the first upload. Once done it opens 
3. [`csrf2.html`](./solve/csrf2.html): Uploads the payload SVG file when the button is clicked. Opens new tab to [`csrf3.html`](./solve/csrf3.html).
4. [`csrf3.html`](./solve/csrf3.html): Using the ObjectID of the first upload, generates a set of predetermined ObjectIDs and tests which one is correct. Once found, it yeets the victim into the SVG file to trigger JavaScript code to grab the flag.
5. Profit??

### Unintended Solution

Turns out the machine and process ID don't change frequently enough to do the full chain of exploits above. The lazy way is.

1. CSRF to XS Leaks to leak Mongo DB Object ID.
2. Submit another URL to determine the Object ID of the SVG payload.

Simplifies things since it can be done in two requests.