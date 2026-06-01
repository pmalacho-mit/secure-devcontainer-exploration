import {
  toPng,
  toJpeg,
  toBlob,
  toPixelData,
  toSvg,
  toCanvas,
} from "html-to-image";

export const downloadURI = (dataurl: string, filename: string) => {
  const link = document.createElement("a");
  link.href = dataurl;
  link.download = filename;
  link.click();
};

const capturers = {
  png: toPng,
  jpeg: toJpeg,
  blob: toBlob,
  pixelData: toPixelData,
  svg: toSvg,
  canvas: toCanvas,
};

export const createCapturer = (root: HTMLElement) => {
  type CaptureKey = keyof typeof capturers;
  type CaptureType<T extends CaptureKey> = (typeof capturers)[T];
  type CaptureOptions<T extends CaptureKey> = Parameters<CaptureType<T>>[1];
  type Capture<T extends CaptureKey> = ReturnType<CaptureType<T>>;

  type CapturedAsString = {
    [k in keyof typeof capturers]: Capture<k> extends Promise<infer U>
      ? /**/ U extends string
        ? /**/ k
        : /**/ never
      : /**/ never;
  }[keyof typeof capturers];

  type Return<T extends CaptureKey> = T extends CapturedAsString
    ? /**/ { uri: Capture<T>; download: (filename: string) => Promise<void> }
    : /**/ Capture<T>;

  return <T extends CaptureKey>(
    type: T,
    options?: CaptureOptions<T>,
  ): Return<T> => {
    const value = capturers[type](root, options);

    switch (type) {
      case "svg":
      case "png":
      case "jpeg":
        const uri = value as Promise<string>;
        return {
          uri,
          download: (filename: string) =>
            uri.then((uri) => downloadURI(uri, filename)),
        } satisfies Return<CapturedAsString> as Return<T>;
      case "blob":
      case "pixelData":
      case "canvas":
        return value as Return<T>;
    }

    throw new Error(`Unsupported capture type: ${type}`);
  };
};
