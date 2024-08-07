{ pkgs, date, ...}:

pkgs.stdenv.mkDerivation rec {
  pname = "presentation";
  version = "1.0.0";
  src = ./.;

  nativeBuildInputs = with pkgs; [
    gnumake
    (texlive.combine {
      inherit (texlive)
      scheme-small
      dirtytalk
      blindtext
      lipsum
      textpos
      latexmk
      latex-bin;
    })
    beamerpresenter
  ];

  buildPhase = ''
    TEXMFHOME=.cache TEXMFVAR=.cache/texmf-var \
      SOURCE_DATE_EPOCH=${date} \
      latexmk -pdf -interaction=nonstopmode -lualatex \
      ebpf.tex
  '';
  installPhase = ''
    mkdir $out
    mv ebpf.pdf $out/
  '';
}
