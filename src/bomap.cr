lib LibC
  fun ntohl(netlong  : UInt32T) : UInt32T
  fun ntohs(netshort : UInt16T) : UInt16T
end

# Byte order mapping
module Bomap
  # expects an instance variable named @raw exists

  macro nop(*names)
    {% for name in names %}
      def {{name}}
        @raw.{{name}}
      end
    {% end %}
  end

  macro n16(*names)
    {% for name in names %}
      def {{name}} : UInt16
        LibC.ntohs(@raw.{{name}})
      end
    {% end %}
  end

  macro n32(*names)
    {% for name in names %}
      def {{name}} : UInt32
        LibC.ntohl(@raw.{{name}})
      end
    {% end %}
  end
end
