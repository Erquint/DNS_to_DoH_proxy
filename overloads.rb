# encoding: ASCII-8BIT
Encoding.default_external = Encoding::ASCII_8BIT
Encoding.default_internal = Encoding::ASCII_8BIT

class Resolv::DNS::Name
  alias :to_s_original :to_s
  def to_s(*full)
    vararg_size = full.size()
    vararg_exception = ArgumentError.new('Wrong number of arguments! ' + 
      "(given #{vararg_size}, expected 0..1)")
    type_exception = ArgumentError.new('Only boolean arguments accepted!')
    
    if vararg_size == 0 then
      return(self.to_s_original())
    elsif vararg_size == 1 then
      full = full.first()
      raise(type_exception) unless [TrueClass, FalseClass].include?(full.class())
      return(self.to_s_original()) unless full
      return(self.to_s_original() + (self.absolute?() ? ?. : ''))
    else
      raise(vararg_exception)
    end
  end
end

class Class
  alias :to_s_original :to_s
  def to_s(*short)
    vararg_size = short.size()
    vararg_exception = ArgumentError.new('Wrong number of arguments! ' + 
      "(given #{vararg_size}, expected 0..1)")
    type_exception = ArgumentError.new('Only boolean arguments accepted!')
    
    if vararg_size == 0 then
      return(self.to_s_original())
    elsif vararg_size == 1 then
      short = short.first()
      raise(type_exception) unless [TrueClass, FalseClass].include?(short.class())
      return(self.to_s_original()) unless short
      return(self.to_s().split('::').last())
    else
      raise(vararg_exception)
    end
  end
end
